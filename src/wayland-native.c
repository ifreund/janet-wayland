#define _POSIX_C_SOURCE 200809L

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <janet.h>
#include <wayland-client-core.h>
#include <wayland-client-protocol.h>
#include <wayland-util.h>

// From libwayland's wayland-private.h
#define WL_CLOSURE_MAX_ARGS 20

static int jwl_interface_gc(void *p, size_t len) {
	(void)len;
	struct wl_interface *interface = p;
	for (int i = 0; i < interface->method_count; i++) {
	    janet_free(interface->methods[i].name);
	    janet_free(interface->methods[i].signature);
	    janet_free(interface->methods[i].types);
	}
	for (int i = 0; i < interface->event_count; i++) {
	    janet_free(interface->events[i].name);
	    janet_free(interface->events[i].signature);
	    janet_free(interface->events[i].types);
	}
	janet_free(interface->name);
	janet_free(interface->methods);
	janet_free(interface->events);
	return 0;
}

// Wrapping each wl_interface in an abstract type is the best way I found to
// integrate into the GC properly. Janet doesn't guarantee an order in
// janet_clear_memory() (How could it? There might be cycles...) so we can't
// iterate over the wl_interfaces table in jwl_display_gc() since the table
// might have already been free'd.
const JanetAbstractType jwl_interface_type = {
	"wayland/interface",
	jwl_interface_gc,
};

struct jwl_display {
	struct wl_display *wl;
	// Stream wrapping the Wayland connection fd
	JanetStream *stream;
	JanetFiber *fiber;
	// Results of the janet_pcall() in jwl_proxy_dispatcher().
	JanetSignal sig;
	Janet ret;
	// Maps interface name (keyword) to janet interface (struct)
	// Populated by (wayland/connect)
	JanetStruct interfaces;
	// Maps interface name (keyword) to jwl_interface (abstract)
	JanetTable *wl_interfaces;
};

static int jwl_display_gcmark(void *p, size_t len) {
	(void)len;
	struct jwl_display *display = p;
	janet_mark(janet_wrap_abstract(display->stream));
	janet_mark(display->ret);
	janet_mark(janet_wrap_struct(display->interfaces));
	janet_mark(janet_wrap_table(display->wl_interfaces));
	return 0;
}

const JanetAbstractType jwl_display_type = {
	"wayland/display",
	NULL, // gc
	jwl_display_gcmark,
};

const JanetAbstractType jwl_proxy_type;
struct jwl_proxy {
	struct jwl_display *display;
	// May be NULL if the proxy has been destroyed.
	struct wl_proxy *wl;
	JanetStruct methods;
	// May be NULL if jwl_proxy_set_listener() is never called.
	JanetFunction *listener;
	Janet user_data;
};

static Janet jwl_proxy_create(struct jwl_display *display, struct wl_proxy *wl, JanetKeyword interface_name) {
	Janet interface_namev = janet_wrap_keyword(interface_name);
	JanetStruct interface = janet_unwrap_struct(janet_struct_get(display->interfaces, interface_namev));
	JanetStruct methods = janet_unwrap_struct(janet_struct_get(interface, janet_ckeywordv("methods")));

	struct jwl_proxy *j = janet_abstract(&jwl_proxy_type, sizeof(struct jwl_proxy));
	j->display = display;
	j->wl = wl;
	j->methods = methods;
	j->listener = NULL;
	j->user_data = janet_wrap_nil();

	wl_proxy_set_user_data(j->wl, j);

	return janet_wrap_abstract(j);
}

static void jwl_proxy_validate(struct jwl_proxy *proxy) {
	if (proxy->wl == NULL) {
		janet_panic("proxy invalid");
	}
	if (proxy->display->wl == NULL) {
		janet_panic("display disconnected");
	}
}

static int jwl_proxy_gc(void *p, size_t len) {
	(void)len;
	struct jwl_proxy *j = p;
	if (j->wl != NULL) {
		assert(wl_proxy_get_user_data(j->wl) == j);
		wl_proxy_set_user_data(j->wl, NULL);
		j->wl = NULL;
	}
	return 0;
}

static int jwl_proxy_gcmark(void *p, size_t len) {
	(void)len;
	struct jwl_proxy *j = p;
	janet_mark(janet_wrap_abstract(j->display));
	janet_mark(janet_wrap_struct(j->methods));
	if (j->listener != NULL) {
		janet_mark(janet_wrap_function(j->listener));
	}
	janet_mark(j->user_data);
	return 0;
}

JANET_FN(jwl_display_disconnect,
		"(wayland/display/disconnect display)",
		"Disconnect from the Wayland server and destroy the display."
		"Invalidates all objects associated with the display.") {
	janet_fixarity(argc, 1);
	struct jwl_proxy *j = janet_getabstract(argv, 0, &jwl_proxy_type);
	jwl_proxy_validate(j);
	wl_display_disconnect(j->display->wl);
	j->wl = NULL;
	j->display->wl = NULL;
	return janet_wrap_nil();
}

JanetSignal jwl_dispatch_pending(struct jwl_display *display, Janet *out) {
	assert(display->sig == JANET_SIGNAL_OK);
	assert(janet_checktype(display->ret, JANET_NIL));

	while (display->sig == JANET_SIGNAL_OK) {
		int dispatched =
			wl_display_dispatch_pending_single(display->wl);
		if (dispatched < 0) {
			*out = janet_cstringv("failed to dispatch pending events");
			return JANET_SIGNAL_ERROR;
		}
		if (dispatched == 0) {
			break;
		}
	}

	JanetSignal sig = display->sig;
	if (sig == JANET_SIGNAL_OK) {
		*out = janet_wrap_nil();
	} else {
		*out = display->ret;
	}
	display->sig = JANET_SIGNAL_OK;
	display->ret = janet_wrap_nil();

	return sig;
}

void jwl_dispatch_end(struct jwl_display *display) {
	assert(display->fiber != NULL);
	JanetFiber *fiber = display->fiber;
	display->fiber = NULL;

	Janet out;
	JanetSignal sig = jwl_dispatch_pending(display, &out);
	janet_schedule_signal(fiber, out, sig);
	janet_async_end(fiber);
}

void jwl_dispatch_cancel(struct jwl_display *display, JanetString msg) {
	assert(display->fiber != NULL);
	JanetFiber *fiber = display->fiber;
	display->fiber = NULL;

	janet_cancel(fiber, janet_wrap_string(msg));
	janet_async_end(fiber);
}

void jwl_dispatch_read_callback(JanetFiber *fiber, JanetAsyncEvent event) {
	struct jwl_display *display = *(struct jwl_display **)fiber->ev_state;
	switch (event) {
	case JANET_ASYNC_EVENT_MARK:
		janet_mark(janet_wrap_abstract(display));
		break;
	case JANET_ASYNC_EVENT_READ: {
		if (wl_display_read_events(display->wl) < 0) {
			jwl_dispatch_cancel(display, janet_formatc(
				"failed to read from Wayland fd: %s", strerror(errno)));
			break;
		}
		jwl_dispatch_end(display);
		break;
	}
	case JANET_ASYNC_EVENT_ERR:
		wl_display_cancel_read(display->wl);
		jwl_dispatch_cancel(display, janet_cstring("stream err"));
		break;
	case JANET_ASYNC_EVENT_HUP:
		wl_display_cancel_read(display->wl);
		jwl_dispatch_cancel(display, janet_cstring("stream hup"));
		break;
	case JANET_ASYNC_EVENT_INIT:
	case JANET_ASYNC_EVENT_DEINIT:
	case JANET_ASYNC_EVENT_CLOSE:
	case JANET_ASYNC_EVENT_WRITE:
	/* Windows stuff */
	case JANET_ASYNC_EVENT_COMPLETE:
	case JANET_ASYNC_EVENT_FAILED:
		break;
	}
}

void jwl_dispatch_write_callback(JanetFiber *fiber, JanetAsyncEvent event) {
	struct jwl_display *display = *(struct jwl_display **)fiber->ev_state;
	switch (event) {
	case JANET_ASYNC_EVENT_MARK:
		janet_mark(janet_wrap_abstract(display));
		break;
	case JANET_ASYNC_EVENT_INIT:
		display->fiber = fiber;
		// fallthrough
	case JANET_ASYNC_EVENT_WRITE: {
		int ret = wl_display_flush(display->wl);
		if (ret < 0 && errno == EAGAIN) {
			// Need to flush again
			break;
		}
		// EPIPE may indicate a protocol error, continue so that it can
		// be read and displayed to the user.
		if (ret < 0 && errno != EPIPE) {
			wl_display_cancel_read(display->wl);
			jwl_dispatch_cancel(display, janet_formatc(
				"failed to write to Wayland fd: %s", strerror(errno)));
			break;
		}
		fiber->ev_stream->write_fiber = NULL;
		fiber->ev_stream->read_fiber = fiber;
		fiber->ev_callback = jwl_dispatch_read_callback;
		break;
	}
	case JANET_ASYNC_EVENT_ERR:
		wl_display_cancel_read(display->wl);
		jwl_dispatch_cancel(display, janet_cstring("stream err"));
		break;
	case JANET_ASYNC_EVENT_HUP:
		wl_display_cancel_read(display->wl);
		jwl_dispatch_cancel(display, janet_cstring("stream hup"));
		break;
	case JANET_ASYNC_EVENT_DEINIT:
	case JANET_ASYNC_EVENT_CLOSE:
	case JANET_ASYNC_EVENT_READ:
	/* Windows stuff */
	case JANET_ASYNC_EVENT_COMPLETE:
	case JANET_ASYNC_EVENT_FAILED:
		break;
	}
}

// Implementation of wl_display_dispatch() that integrates with the janet event loop
JANET_FN(jwl_display_dispatch,
		"(display/dispatch display)",
		"Write requests to the Wayland connection, read events from the server, "
		"and invoke event listeners. Uses non-blocking I/O integrated with "
		"Janet's event loop.") {
	janet_fixarity(argc, 1);
	struct jwl_proxy *j = janet_getabstract(argv, 0, &jwl_proxy_type);
	jwl_proxy_validate(j);
	if (wl_display_prepare_read(j->display->wl) == -1) {
		Janet out;
		JanetSignal sig = jwl_dispatch_pending(j->display, &out);
		janet_signalv(sig, out);
	}
	struct jwl_display **ev_state = janet_malloc(sizeof(struct jwl_display **));
	*ev_state = j->display;
	janet_async_start(j->display->stream, JANET_ASYNC_LISTEN_WRITE, jwl_dispatch_write_callback, ev_state);
}

static struct wl_interface *jwl_get_wl_interface(JanetStruct interfaces,
		JanetTable *wl_interfaces, Janet namev);

static char *jwl_strdup(const char *s) {
	size_t len = strlen(s);
	char *new = janet_malloc(len + 1);
	if (new == NULL) {
		JANET_OUT_OF_MEMORY;
	}
	return memcpy(new, s, len + 1);
}

static struct wl_message jwl_get_wl_message(JanetStruct interfaces,
		JanetTable *wl_interfaces, Janet messagev) {
	JanetStruct message = janet_unwrap_struct(messagev);
	struct wl_message wl;

	Janet namev = janet_struct_get(message, janet_ckeywordv("name"));
	wl.name = jwl_strdup(janet_unwrap_string(namev));

	Janet signaturev = janet_struct_get(message, janet_ckeywordv("signature"));
	wl.signature = jwl_strdup((char *)janet_unwrap_string(signaturev));

	Janet typesv = janet_struct_get(message, janet_ckeywordv("types"));
	JanetTuple types = janet_unwrap_tuple(typesv);
	wl.types = janet_malloc(janet_tuple_length(types) * sizeof(struct wl_interface *));
	if (wl.types == NULL) {
		JANET_OUT_OF_MEMORY;
	}
	for (int32_t i = 0; i < janet_tuple_length(types); i++) {
		if (janet_checktype(types[i], JANET_NIL)) {
			wl.types[i] = NULL;
		} else {
			wl.types[i] = jwl_get_wl_interface(interfaces, wl_interfaces, types[i]);
		}
	}

	return wl;
}

static struct wl_interface *jwl_get_wl_interface(JanetStruct interfaces,
		JanetTable *wl_interfaces, Janet namev) {
	Janet existing = janet_table_get(wl_interfaces, namev);
	if (janet_checktype(existing, JANET_ABSTRACT)) {
		return janet_unwrap_abstract(existing);
	}

	JanetStruct interface = janet_unwrap_struct(janet_struct_get(interfaces, namev));

	struct wl_interface *wl = janet_abstract(&jwl_interface_type, sizeof(struct wl_interface));
	if (wl == NULL) {
		JANET_OUT_OF_MEMORY;
	}
	janet_table_put(wl_interfaces, namev, janet_wrap_abstract(wl));

	wl->name = jwl_strdup(janet_unwrap_keyword(namev));
	wl->version = janet_unwrap_integer(janet_struct_get(interface, janet_ckeywordv("version")));

	JanetTuple requests = janet_unwrap_tuple(janet_struct_get(interface, janet_ckeywordv("requests")));
	wl->method_count = janet_tuple_length(requests);
	wl->methods = janet_malloc(janet_tuple_length(requests) * sizeof(struct wl_message));
	if (wl->methods == NULL) {
		JANET_OUT_OF_MEMORY;
	}
	for (int32_t i = 0; i < janet_tuple_length(requests); i++) {
		((struct wl_message *)wl->methods)[i] =
			jwl_get_wl_message(interfaces, wl_interfaces, requests[i]);
	}

	JanetTuple events = janet_unwrap_tuple(janet_struct_get(interface, janet_ckeywordv("events")));
	wl->event_count = janet_tuple_length(events);
	wl->events = janet_malloc(janet_tuple_length(events) * sizeof(struct wl_message));
	if (wl->events == NULL) {
		JANET_OUT_OF_MEMORY;
	}
	for (int32_t i = 0; i < janet_tuple_length(events); i++) {
		((struct wl_message *)wl->events)[i] =
			jwl_get_wl_message(interfaces, wl_interfaces, events[i]);
	}

	return wl;
}

static const char *jwl_signature_iter(const char *s, char *type, bool *allow_null) {
	*allow_null = false;
	for (; *s; s++) {
		switch (*s) {
		case 'i':
		case 'u':
		case 'f':
		case 's':
		case 'o':
		case 'n':
		case 'a':
		case 'h':
			*type = *s;
			return s + 1;
		case '?':
			*allow_null = true;
			continue;
		default:
			continue;
		}
	}
	return s;
}

JANET_FN(jwl_proxy_request_raw,
		"(proxy/request-raw proxy opcode interface version flags args",
		"") {
	janet_fixarity(argc, 6);
	struct jwl_proxy *j = janet_getabstract(argv, 0, &jwl_proxy_type);
	jwl_proxy_validate(j);
	uint32_t opcode = janet_getuinteger(argv, 1);
	JanetKeyword interface_name = janet_optkeyword(argv, argc, 2, NULL);
	uint32_t version = janet_getuinteger(argv, 3);
	JanetStruct flags = janet_getstruct(argv, 4);
	JanetTuple args = janet_gettuple(argv, 5);

	const struct wl_interface *wl_interface = NULL;
	if (interface_name != NULL) {
		wl_interface = jwl_get_wl_interface(j->display->interfaces, j->display->wl_interfaces,
			janet_wrap_keyword(interface_name));
		if (version == 0) {
			version = wl_proxy_get_version(j->wl);
		}
	}

	uint32_t wl_flags = 0;
	if (janet_truthy(janet_struct_get(flags, janet_ckeywordv("destroy")))) {
		wl_flags |= WL_MARSHAL_FLAG_DESTROY;
	}

	union wl_argument wl_args[WL_CLOSURE_MAX_ARGS];
	// It's unlikely that a single message will ever have 20 array arguments, but
	// this approach avoids dynamic memory allocation and is quite simple.
	struct wl_array arrays[WL_CLOSURE_MAX_ARGS];

	const struct wl_message *message = &wl_proxy_get_interface(j->wl)->methods[opcode];
	const char *signature = message->signature;
	for (int32_t i = 0; i < janet_tuple_length(args); i++) {
		if (!*signature) {
			janet_panicf("too many arguments");
		}
		char type;
		bool allow_null;
		signature = jwl_signature_iter(signature, &type, &allow_null);
		switch (type) {
		case 'i':
			wl_args[i] = (union wl_argument){ .i = janet_getinteger(args, i)  };
			break;
		case 'u':
			wl_args[i] = (union wl_argument){ .u = janet_getuinteger(args, i)  };
			break;
		case 'f':
			wl_args[i] = (union wl_argument){ .f = wl_fixed_from_double(janet_getnumber(args, i)) };
			break;
		case 's':
			if (allow_null && janet_checktype(args[i], JANET_NIL)) {
				wl_args[i] = (union wl_argument){ .s = NULL };
				break;
			}
			wl_args[i] = (union wl_argument){ .s = janet_getcstring(args, i) };
			break;
		case 'o': {
			if (allow_null && janet_checktype(args[i], JANET_NIL)) {
				wl_args[i] = (union wl_argument){ .o = NULL };
				break;
			}
			struct jwl_proxy *o = janet_getabstract(args, i, &jwl_proxy_type);
			const struct wl_interface *expected = message->types[i];
			if (o->wl == NULL) {
				janet_panicf("expected <wayland/proxy (%s)>, got %v", expected->name, args[i]);
			}
			if (expected != NULL && wl_proxy_get_interface(o->wl) != expected) {
				janet_panicf("expected <wayland/proxy (%s)>, got %v", expected->name, args[i]);
			}
			wl_args[i] = (union wl_argument){ .o = (struct wl_object *)o->wl };
			break;
		}
		case 'n':
			wl_args[i] = (union wl_argument){ .o = NULL };
			break;
		case 'a': {
			JanetByteView v = janet_getbytes(args, i);
			// Casting away the const here is ok, libwayland won't modify the bytes.
			arrays[i] = (struct wl_array){
				.alloc = v.len,
				.data = (uint8_t *)v.bytes,
				.size = v.len,
			};
			wl_args[i] = (union wl_argument){ .a = &arrays[i] };
			break;
		}
		case 'h':
			wl_args[i] = (union wl_argument){ .h = janet_getinteger(args, i) };
			break;
		default:
			assert(false);
		}
	}
	if (*signature) {
		janet_panicf("not enough arguments");
	}

	// In order to ensure the request is actually sent promptly, we need to
	// interrupt any ongoing dispatch. Otherwise the request may not be
	// actually written to the Wayland fd until after the server sends
	// some event that wakes up the fiber reading from the Wayland fd.
	if (j->display->fiber != NULL) {
		wl_display_cancel_read(j->display->wl);
		jwl_dispatch_end(j->display);
	}

	struct wl_proxy *new_wl = wl_proxy_marshal_array_flags(j->wl, opcode,
		wl_interface, version, wl_flags, wl_args);
	if ((wl_flags & WL_MARSHAL_FLAG_DESTROY) != 0) {
		j->wl = NULL;
	}
	if (new_wl == NULL) {
		if (wl_interface != NULL) {
			JANET_OUT_OF_MEMORY;
		}
		return janet_wrap_nil();
	} else {
		assert(wl_interface != NULL);
		return jwl_proxy_create(j->display, new_wl, interface_name);
	}
}

static Janet snake_to_kebab_keywordv(const char *snake) {
	char *kebab = strdup(snake);
	for (char *i = kebab; *i; i++) {
		if (*i == '_') {
			*i = '-';
		}
	}
	Janet ret = janet_ckeywordv(kebab);
	free(kebab);
	return ret;
}

static int jwl_proxy_dispatcher(const void *user_data, void *target, uint32_t opcode,
	const struct wl_message *msg, union wl_argument *wl_args) {
	struct wl_proxy *wl = target;
	struct jwl_proxy *j = wl_proxy_get_user_data(wl);
	assert(j->wl == wl);

	JanetStruct interface = janet_unwrap_struct(janet_struct_get(j->display->interfaces,
		janet_ckeywordv(wl_proxy_get_interface(wl)->name)));
	JanetTuple events = janet_unwrap_tuple(janet_struct_get(interface, janet_ckeywordv("events")));
	assert(opcode < janet_tuple_length(events));
	JanetTuple enums = janet_unwrap_tuple(
		janet_struct_get(janet_unwrap_struct(events[opcode]), janet_ckeywordv("enums")));

	Janet eventvs[WL_CLOSURE_MAX_ARGS + 1];

	eventvs[0] = snake_to_kebab_keywordv(msg->name);

	int32_t i = 0;
	const char *signature = msg->signature;
	while (*signature) {
		char type;
		bool allow_null;
		signature = jwl_signature_iter(signature, &type, &allow_null);
		switch (type) {
		case 'i': {
			Janet v = janet_wrap_number(wl_args[i].i);
			if (janet_checktype(enums[i], JANET_FUNCTION)) {
				Janet out;
				JanetSignal sig = janet_pcall(janet_unwrap_function(enums[i]),
					1, (const Janet []){v}, &out, NULL);
				if (sig != JANET_SIGNAL_OK) {
					j->display->sig = sig;
					j->display->ret = out;
					return 0;
				}
				eventvs[i + 1] = out;
			} else {
				eventvs[i + 1] = v;
			}
			break;
		}
		case 'u': {
			Janet v = janet_wrap_number(wl_args[i].u);
			if (janet_checktype(enums[i], JANET_FUNCTION)) {
				Janet out;
				JanetSignal sig = janet_pcall(janet_unwrap_function(enums[i]),
					1, (const Janet []){v}, &out, NULL);
				if (sig != JANET_SIGNAL_OK) {
					j->display->sig = sig;
					j->display->ret = out;
					return 0;
				}
				eventvs[i + 1] = out;
			} else {
				eventvs[i + 1] = v;
			}
			break;
		}
		case 'f':
			eventvs[i + 1] = janet_wrap_number(wl_fixed_to_double(wl_args[i].f));
			break;
		case 's':
			if (wl_args[i].s == NULL) {
				eventvs[i + 1] = janet_wrap_nil();
			} else {
				eventvs[i + 1] = janet_cstringv(wl_args[i].s);
			}
			break;
		case 'o':
			if (wl_args[i].o == NULL) {
				eventvs[i + 1] = janet_wrap_nil();
			} else {
				struct wl_proxy *other_wl = (struct wl_proxy *)wl_args[i].o;
				struct jwl_proxy *other_j = wl_proxy_get_user_data(other_wl);
				assert(other_j->wl == other_wl);
				eventvs[i + 1] = janet_wrap_abstract(other_j);
			}
			break;
		case 'n': {
			// libwayland-client creates wl_proxy objects for new_id arguments
			// when events are queued before calling our dispatcher.
			struct wl_proxy *new_wl = (struct wl_proxy *)wl_args[i].o;
			eventvs[i + 1] = jwl_proxy_create(j->display, new_wl, janet_ckeyword(msg->types[i]->name));
			break;
		}
		case 'a': {
			eventvs[i + 1] = janet_stringv(wl_args[i].a->data, wl_args[i].a->size);
			break;
		}
		case 'h':
			eventvs[i + 1] = janet_wrap_number(wl_args[i].h);
			break;
		default:
			assert(false);
		}
		i++;
	}

	Janet event = janet_wrap_tuple(janet_tuple_n(eventvs, i + 1));
	if (janet_checktype(j->user_data, JANET_NIL)) {
		j->display->sig = janet_pcall(j->listener,
			2, (const Janet []){janet_wrap_abstract(j), event},
			&j->display->ret, NULL);
	} else {
		j->display->sig = janet_pcall(j->listener,
			3, (const Janet []){janet_wrap_abstract(j), event, j->user_data},
			&j->display->ret, NULL);
	}

	return 0;
}

JANET_FN(jwl_proxy_set_listener,
		"(proxy/set-listener proxy listener &opt user-data)",
		"") {
	janet_arity(argc, 2, 3);
	struct jwl_proxy *j = janet_getabstract(argv, 0, &jwl_proxy_type);
	jwl_proxy_validate(j);
	JanetFunction *listener = janet_getfunction(argv, 1);
	if (j->listener != NULL) {
		janet_panic("proxy already has a listener");
	}
	j->listener = listener;
	if (argc == 3) {
		j->user_data = argv[2];
	}
	wl_proxy_add_dispatcher(j->wl, jwl_proxy_dispatcher, NULL, j);
	return janet_wrap_nil();
}

JANET_FN(jwl_proxy_get_user_data,
		"(proxy/get-user-data proxy)",
		"") {
	janet_fixarity(argc, 1);
	struct jwl_proxy *j = janet_getabstract(argv, 0, &jwl_proxy_type);
	jwl_proxy_validate(j);
	return j->user_data;
}

JANET_FN(jwl_proxy_destroy,
		"(proxy/destroy proxy)",
		"") {
	janet_fixarity(argc, 1);
	struct jwl_proxy *j = janet_getabstract(argv, 0, &jwl_proxy_type);
	jwl_proxy_validate(j);
	if (j->wl == (struct wl_proxy *)j->display->wl) {
		janet_panic("display may only be destroyed with display/disconnect");
	}
	wl_proxy_destroy(j->wl);
	j->wl = NULL;
	return janet_wrap_nil();
}

static int jwl_proxy_get(void *p, Janet key, Janet *out) {
	struct jwl_proxy *j = p;
	*out = janet_struct_get(j->methods, key);
	return 1;
}

static void jwl_proxy_tostring(void *p, JanetBuffer *buffer) {
	struct jwl_proxy *j = p;
	if (j->wl == NULL) {
		janet_buffer_push_cstring(buffer, "(invalid)");
	} else {
		janet_buffer_push_u8(buffer, '(');
		janet_buffer_push_cstring(buffer, wl_proxy_get_class(j->wl));
		janet_buffer_push_u8(buffer, '#');
		char id[32];
		snprintf(id, sizeof(id), "%" PRIu32, wl_proxy_get_id(j->wl));
		janet_buffer_push_cstring(buffer, id);
		janet_buffer_push_u8(buffer, ')');
	}
}

const JanetAbstractType jwl_proxy_type = {
	"wayland/proxy",
	jwl_proxy_gc,
	jwl_proxy_gcmark,
	jwl_proxy_get,
	NULL, // put
	NULL, // marshal
	NULL, // unmarshal
	jwl_proxy_tostring,
	NULL, // compare
	NULL, // hash
	NULL, // next
	NULL, // call
	NULL, // length
	NULL, // bytes
};

static void jwl_check_message(Janet messagev, JanetStruct interfaces) {
	if (!janet_checktype(messagev, JANET_STRUCT)) {
		janet_panicf("expected message struct, got %v", messagev);
	}
	JanetStruct message = janet_unwrap_struct(messagev);

	Janet namev = janet_struct_get(message, janet_ckeywordv("name"));
	if (!janet_checktype(namev, JANET_STRING)) {
		janet_panicf("expected string message :name, got %v", namev);
	}

	Janet signaturev = janet_struct_get(message, janet_ckeywordv("signature"));
	if (!janet_checktype(signaturev, JANET_STRING)) {
		janet_panicf("expected string message :signature, got %v", signaturev);
	}
	const uint8_t *signature = janet_unwrap_string(signaturev);
	for (; *signature; signature++) {
		if (*signature >= '0' && *signature <= '9') {
			continue;
		}
		switch (*signature) {
		case 'i':
		case 'u':
		case 'f':
		case 's':
		case 'o':
		case 'n':
		case 'a':
		case 'h':
		case '?':
			continue;
		default:
			janet_panicf("invalid message signature %v", signaturev);
		}
	}

	Janet typesv = janet_struct_get(message, janet_ckeywordv("types"));
	if (!janet_checktype(typesv, JANET_TUPLE)) {
		janet_panicf("expected tuple message :types, got %v", typesv);
	}
	JanetTuple types = janet_unwrap_tuple(typesv);
	for (int32_t i = 0; i < janet_tuple_length(types); i++) {
		if (janet_checktype(types[i], JANET_KEYWORD)) {
			if (janet_checktype(janet_struct_get(interfaces, types[i]), JANET_NIL)) {
				janet_panicf("unknown interface %v in message :types", types[i]);
			}
		} else if (!janet_checktype(types[i], JANET_NIL)) {
			janet_panicf("invalid value %v in message :types", types[i]);
		}
	}

	Janet enumsv = janet_struct_get(message, janet_ckeywordv("enums"));
	if (!janet_checktype(enumsv, JANET_TUPLE)) {
		janet_panicf("expected tuple message :enums, got %v", enumsv);
	}
	JanetTuple enums = janet_unwrap_tuple(enumsv);
	for (int32_t i = 0; i < janet_tuple_length(enums); i++) {
		if (!janet_checktype(enums[i], JANET_FUNCTION) &&
			!janet_checktype(enums[i], JANET_NIL)) {
			janet_panicf("invalid value %v in message :enums", enums[i]);
		}
	}
}

static void jwl_check_interface(Janet interfacev, JanetStruct interfaces) {
	if (!janet_checktype(interfacev, JANET_STRUCT)) {
		janet_panicf("expected interface struct, got %v", interfacev);
	}
	JanetStruct interface = janet_unwrap_struct(interfacev);

	Janet versionv = janet_struct_get(interface, janet_ckeywordv("version"));
	if (!janet_checkuint(versionv)) {
		janet_panicf("expected u32 interface :version, got %v", versionv);
	}

	Janet requestsv = janet_struct_get(interface, janet_ckeywordv("requests"));
	if (!janet_checktype(requestsv, JANET_TUPLE)) {
		janet_panicf("expected tuple interface :requests, got %v", requestsv);
	}
	JanetTuple requests = janet_unwrap_tuple(requestsv);
	for (int32_t i = 0; i < janet_tuple_length(requests); i++) {
		jwl_check_message(requests[i], interfaces);
	}

	Janet eventsv = janet_struct_get(interface, janet_ckeywordv("events"));
	if (!janet_checktype(eventsv, JANET_TUPLE)) {
		janet_panicf("expected tuple interface :events, got %v", eventsv);
	}
	JanetTuple events = janet_unwrap_tuple(eventsv);
	for (int32_t i = 0; i < janet_tuple_length(events); i++) {
		jwl_check_message(events[i], interfaces);
	}

	Janet methodsv = janet_struct_get(interface, janet_ckeywordv("methods"));
	if (!janet_checktype(methodsv, JANET_STRUCT)) {
		janet_panicf("expected struct interface :methods, got %v", methodsv);
	}
}

JANET_FN(jwl_connect,
		"(wayland/connect interfaces &opt name)",
		"Connect to a Wayland server."
		"The interfaces argument should be the struct returned by (wayland/scan)."
		"The optional name argument is passed on to libwayland."
		"See docs for libwayland's wl_display_connect() for details.") {
	janet_arity(argc, 1, 2);
	JanetStruct interfaces = janet_getstruct(argv, 0);
	const char *name = janet_optcstring(argv, argc, 1, NULL);

	for (int32_t i = 0; i < janet_struct_length(interfaces); i++) {
		if (janet_checktype(interfaces[i].key, JANET_NIL)) {
			continue; // empty slot
		}
		jwl_check_interface(interfaces[i].value, interfaces);
	}

	JanetStruct interface = janet_unwrap_struct(
		janet_struct_get(interfaces, janet_ckeywordv("wl_display")));
	JanetStruct methods = janet_unwrap_struct(
		janet_struct_get(interface, janet_ckeywordv("methods")));

	struct wl_display *wl = wl_display_connect(name);
	if (!wl) {
		janet_panicf("unable to connect to wayland server: %s", strerror(errno));
	}

	// The fd should only be closed by wl_display_disconnect()
	JanetStream *stream = janet_stream(wl_display_get_fd(wl),
		JANET_STREAM_READABLE | JANET_STREAM_WRITABLE | JANET_STREAM_NOT_CLOSEABLE, NULL);

	struct jwl_display *display = janet_abstract(&jwl_display_type, sizeof(struct jwl_display));
	display->wl = wl;
	display->stream = stream;
	display->fiber = NULL;
	display->sig = JANET_SIGNAL_OK;
	display->ret = janet_wrap_nil();
	display->interfaces = interfaces;
	display->wl_interfaces = janet_table(0);

	struct jwl_proxy *j = janet_abstract(&jwl_proxy_type, sizeof(struct jwl_proxy));
	j->display = display;
	j->wl = (struct wl_proxy *)wl;
	j->methods = methods;
	j->listener = NULL;
	j->user_data = janet_wrap_nil();
	wl_proxy_set_user_data(j->wl, j);

	return janet_wrap_abstract(j);
}

JANET_MODULE_ENTRY(JanetTable *env) {
	JanetRegExt cfuns[] = {
		JANET_REG("connect", jwl_connect),
		JANET_REG("display/disconnect", jwl_display_disconnect),
		JANET_REG("display/dispatch", jwl_display_dispatch),
		JANET_REG("proxy/set-listener", jwl_proxy_set_listener),
		JANET_REG("proxy/get-user-data", jwl_proxy_get_user_data),
		JANET_REG("proxy/request-raw", jwl_proxy_request_raw),
		JANET_REG("proxy/destroy", jwl_proxy_destroy),
		JANET_REG_END,
	};
	janet_cfuns_ext(env, "wayland-native", cfuns);
}
