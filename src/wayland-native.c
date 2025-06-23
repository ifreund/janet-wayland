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

const JanetAbstractType jwl_proxy_type;
struct jwl_proxy {
	// May be NULL if the proxy has been destroyed.
	struct wl_proxy *wl;
	JanetFunction *send;
	// May be NULL if jwl_proxy_set_listener() is never called.
	JanetFunction *listener;
	Janet user_data;
	// Maps interface name (keyword) to janet interface (struct)
	// Populated by jwl_display_connect()
	// NULL if not a wl_display
	// TODO don't waste memory by having this field present for every wl_proxy
	JanetStruct interfaces;
	// Maps interface name (keyword) to wl_interface (pointer)
	// NULL if not a wl_display
	// TODO don't waste memory by having this field present for every wl_proxy
	JanetTable *wl_interfaces;
};

static Janet jwl_proxy_create(struct wl_proxy *wl, JanetKeyword interface_name) {
	struct jwl_proxy *display = wl_proxy_get_user_data((struct wl_proxy *)wl_proxy_get_display(wl));
	assert(display->interfaces != NULL);
	assert(display->wl_interfaces != NULL);

	Janet interface_namev = janet_wrap_keyword(interface_name);
	JanetStruct interface = janet_unwrap_struct(janet_struct_get(display->interfaces, interface_namev));
	JanetFunction *send = janet_unwrap_function(janet_struct_get(interface, janet_ckeywordv("send")));

	struct jwl_proxy *j = janet_abstract(&jwl_proxy_type, sizeof(struct jwl_proxy));
	j->wl = wl;
	j->send = send;
	j->listener = NULL;
	j->user_data = janet_wrap_nil();
	j->interfaces = NULL;
	j->wl_interfaces = NULL;

	wl_proxy_set_user_data(j->wl, j);

	return janet_wrap_abstract(j);
}

static int jwl_proxy_gc(void *p, size_t len) {
	(void)len;
	struct jwl_proxy *j = p;
	if (j->wl != NULL) {
		assert(wl_proxy_get_user_data(j->wl) == j);
		wl_proxy_set_user_data(j->wl, NULL);
		j->wl = NULL;
	}
	// TODO is it safe to free the wl_interfaces when the wl_display is garbage collected?
	return 0;
}

static int jwl_proxy_gcmark(void *p, size_t len) {
	(void)len;
	struct jwl_proxy *j = p;
	janet_mark(janet_wrap_function(j->send));
	janet_mark(j->user_data);
	if (j->listener != NULL) {
		janet_mark(janet_wrap_function(j->listener));
	}
	if (j->interfaces != NULL) {
		janet_mark(janet_wrap_struct(j->interfaces));
	}
	if (j->wl_interfaces != NULL) {
		janet_mark(janet_wrap_table(j->wl_interfaces));
	}
	return 0;
}

JANET_FN(jwl_display_disconnect,
		"(wl/display-disconnect display)",
		"See libwayland's wl_display_disconnect") {
	janet_fixarity(argc, 1);
	struct jwl_proxy *j = janet_getabstract(argv, 0, &jwl_proxy_type);
	if (j->wl == NULL) {
		janet_panic("proxy invalid");
	}
	wl_display_disconnect((struct wl_display *)j->wl);
	j->wl = NULL;
	return janet_wrap_nil();
}

JANET_FN(jwl_display_roundtrip,
		"(wl/display-roundtrip display)",
		"See libwayland's wl_display_roundtrip") {
	janet_fixarity(argc, 1);
	struct jwl_proxy *j = janet_getabstract(argv, 0, &jwl_proxy_type);
	if (j->wl == NULL) {
		janet_panic("proxy invalid");
	}
	wl_display_roundtrip((struct wl_display *)j->wl);
	return janet_wrap_nil();
}

JANET_FN(jwl_display_dispatch,
		"(wl/display-dispatch display)",
		"See libwayland's wl_display_dispatch") {
	janet_fixarity(argc, 1);
	struct jwl_proxy *j = janet_getabstract(argv, 0, &jwl_proxy_type);
	if (j->wl == NULL) {
		janet_panic("proxy invalid");
	}
	wl_display_dispatch((struct wl_display *)j->wl);
	return janet_wrap_nil();
}

JanetMethod jwl_display_methods[] = {
	{"disconnect", jwl_display_disconnect },
	{"roundtrip", jwl_display_roundtrip },
	{"dispatch", jwl_display_dispatch },
	{NULL, NULL},
};

static struct wl_interface *jwl_get_wl_interface(JanetStruct interfaces,
		JanetTable *wl_interfaces, Janet namev);

static struct wl_message jwl_get_wl_message(JanetStruct interfaces,
		JanetTable *wl_interfaces, Janet messagev) {
	JanetStruct message = janet_unwrap_struct(messagev);
	struct wl_message wl;

	Janet namev = janet_struct_get(message, janet_ckeywordv("name"));
	wl.name = strdup((char *)janet_unwrap_string(namev));
	if (wl.name == NULL) {
		JANET_OUT_OF_MEMORY;
	}

	Janet signaturev = janet_struct_get(message, janet_ckeywordv("signature"));
	wl.signature = strdup((char *)janet_unwrap_string(signaturev));
	if (wl.signature == NULL) {
		JANET_OUT_OF_MEMORY;
	}

	Janet typesv = janet_struct_get(message, janet_ckeywordv("types"));
	JanetTuple types = janet_unwrap_tuple(typesv);

	wl.types = malloc(janet_tuple_length(types) * sizeof(struct wl_interface *));
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
	if (janet_checktype(existing, JANET_POINTER)) {
		return janet_unwrap_pointer(existing);
	}

	JanetStruct interface = janet_unwrap_struct(janet_struct_get(interfaces, namev));

	struct wl_interface *wl = malloc(sizeof(struct wl_interface));
	if (wl == NULL) {
		JANET_OUT_OF_MEMORY;
	}
	janet_table_put(wl_interfaces, namev, janet_wrap_pointer(wl));

	wl->name = strdup((char *)janet_unwrap_keyword(namev));
	if (wl->name == NULL) {
		JANET_OUT_OF_MEMORY;
	}
	wl->version = janet_unwrap_integer(janet_struct_get(interface, janet_ckeywordv("version")));

	JanetTuple requests = janet_unwrap_tuple(janet_struct_get(interface, janet_ckeywordv("requests")));
	wl->method_count = janet_tuple_length(requests);
	wl->methods = malloc(janet_tuple_length(requests) * sizeof(struct wl_message));
	if (wl->methods == NULL) {
		JANET_OUT_OF_MEMORY;
	}
	for (int32_t i = 0; i < janet_tuple_length(requests); i++) {
		((struct wl_message *)wl->methods)[i] =
			jwl_get_wl_message(interfaces, wl_interfaces, requests[i]);
	}

	JanetTuple events = janet_unwrap_tuple(janet_struct_get(interface, janet_ckeywordv("events")));
	wl->event_count = janet_tuple_length(events);
	wl->events = malloc(janet_tuple_length(events) * sizeof(struct wl_message));
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

JANET_FN(jwl_proxy_send_raw,
		"(wl/proxy-send-raw proxy opcode interface version flags args)",
		"Calls wl_proxy_marshal_array_flags() internally") {
	janet_fixarity(argc, 6);
	struct jwl_proxy *j = janet_getabstract(argv, 0, &jwl_proxy_type);
	if (j->wl == NULL) {
		janet_panic("proxy invalid");
	}
	uint32_t opcode = janet_getuinteger(argv, 1);
	JanetKeyword interface_name = janet_optkeyword(argv, argc, 2, NULL);
	uint32_t version = janet_getuinteger(argv, 3);
	JanetStruct flags = janet_getstruct(argv, 4);
	JanetTuple args = janet_gettuple(argv, 5);

	struct jwl_proxy *display = wl_proxy_get_user_data((struct wl_proxy *)wl_proxy_get_display(j->wl));
	assert(display->interfaces != NULL);
	assert(display->wl_interfaces != NULL);

	const struct wl_interface *wl_interface = NULL;
	if (interface_name != NULL) {
		wl_interface = jwl_get_wl_interface(display->interfaces, display->wl_interfaces,
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
				janet_panicf("expected <wl/proxy (%s)>, got %v", expected->name, args[i]);
			}
			if (expected != NULL && wl_proxy_get_interface(o->wl) != expected) {
				janet_panicf("expected <wl/proxy (%s)>, got %v", expected->name, args[i]);
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

	struct wl_proxy *new_wl = wl_proxy_marshal_array_flags(j->wl, opcode,
		wl_interface, version, wl_flags, wl_args);
	if (new_wl == NULL) {
		if (wl_interface != NULL) {
			JANET_OUT_OF_MEMORY;
		}
		return janet_wrap_nil();
	} else {
		assert(wl_interface != NULL);
		return jwl_proxy_create(new_wl, interface_name);
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

	struct jwl_proxy *display = wl_proxy_get_user_data((struct wl_proxy *)wl_proxy_get_display(j->wl));
	assert(display->interfaces != NULL);
	assert(display->wl_interfaces != NULL);

	JanetStruct interface = janet_unwrap_struct(janet_struct_get(display->interfaces,
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
				eventvs[i + 1] = janet_call(janet_unwrap_function(enums[i]), 1, (const Janet []){v});
			} else {
				eventvs[i + 1] = v;
			}
			break;
		}
		case 'u': {
			Janet v = janet_wrap_number(wl_args[i].u);
			if (janet_checktype(enums[i], JANET_FUNCTION)) {
				eventvs[i + 1] = janet_call(janet_unwrap_function(enums[i]), 1, (const Janet []){v});
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
			eventvs[i + 1] = jwl_proxy_create(new_wl, janet_ckeyword(msg->types[i]->name));
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

	JanetTuple event = janet_tuple_n(eventvs, i + 1);

	if (janet_checktype(j->user_data, JANET_NIL)) {
		janet_call(j->listener, 2, (const Janet []){
			janet_wrap_abstract(j),
			janet_wrap_tuple(event),
		});
	} else {
		janet_call(j->listener, 3, (const Janet[]){
			janet_wrap_abstract(j),
			janet_wrap_tuple(event),
			j->user_data,
		});
	}

	return 0;
}

JANET_FN(jwl_proxy_set_listener,
		"(wl/proxy-set-listener proxy listener &opt user-data)", "") {
	janet_arity(argc, 2, 3);
	struct jwl_proxy *j = janet_getabstract(argv, 0, &jwl_proxy_type);
	if (j->wl == NULL) {
		janet_panic("proxy invalid");
	}

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
		"(wl/proxy-get-user-data proxy)", "") {
	janet_fixarity(argc, 1);
	struct jwl_proxy *j = janet_getabstract(argv, 0, &jwl_proxy_type);
	if (j->wl == NULL) {
		janet_panic("proxy invalid");
	}
	return j->user_data;
}

JanetMethod jwl_proxy_methods[] = {
	{"send-raw", jwl_proxy_send_raw},
	{"set-listener", jwl_proxy_set_listener},
	{"get-user-data", jwl_proxy_get_user_data},
	{NULL, NULL},
};

static int jwl_proxy_get(void *p, Janet key, Janet *out) {
	struct jwl_proxy *j = p;
	if (!janet_checktype(key, JANET_KEYWORD)) {
		return 0;
	}

	JanetKeyword method = janet_unwrap_keyword(key);

	if (janet_getmethod(method, jwl_proxy_methods, out)) {
		return 1;
	}

	if (j->wl == NULL) {
		janet_panic("proxy invalid");
	}
	if (wl_proxy_get_interface(j->wl) == &wl_display_interface) {
		if (janet_getmethod(method, jwl_display_methods, out)) {
			return 1;
		}
	}

	Janet args[1] = { key };
	*out = janet_call(j->send, 1, args);
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
	"wl/proxy",
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

	Janet sendv = janet_struct_get(interface, janet_ckeywordv("send"));
	if (!janet_checktype(sendv, JANET_FUNCTION)) {
		janet_panicf("expected function interface :send, got %v", sendv);
	}
}

JANET_FN(jwl_display_connect,
		"(wl/display-connect interfaces &opt name)",
		"Connect to a Wayland server."
		"The interfaces argument should be the struct returned by (wl/scan)."
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
	JanetFunction *send = janet_unwrap_function(
		janet_struct_get(interface, janet_ckeywordv("send")));

	struct wl_display *wl = wl_display_connect(name);
	if (!wl) {
		janet_panicf("unable to connect to wayland server: %s", strerror(errno));
	}

	struct jwl_proxy *j = janet_abstract(&jwl_proxy_type, sizeof(struct jwl_proxy));
	j->wl = (struct wl_proxy *)wl;
	j->send = send;
	j->listener = NULL;
	j->user_data = janet_wrap_nil();
	j->interfaces = interfaces;
	j->wl_interfaces = janet_table(0);
	wl_proxy_set_user_data(j->wl, j);

	return janet_wrap_abstract(j);
}

JANET_MODULE_ENTRY(JanetTable *env) {
	JanetRegExt cfuns[] = {
		JANET_REG("display-connect", jwl_display_connect),
		JANET_REG_END,
	};
	janet_cfuns_ext(env, "wayland-native", cfuns);
}
