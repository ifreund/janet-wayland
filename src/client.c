#include <assert.h>
#include <errno.h>
#include <stdbool.h>

#include <janet.h>
#include <stdint.h>
#include <wayland-client-core.h>
#include <wayland-client-protocol.h>
#include <wayland-util.h>

// From libwayland's wayland-private.h
#define WL_CLOSURE_MAX_ARGS 20

// Maps interface name to wl_interface pointer
JanetTable wl_interfaces;
// The display is a special case as it is created through (wl/display/connect)
// rather than by sending a request.
Janet wl_display_send;

const JanetAbstractType jwl_proxy_type;
struct jwl_proxy {
	// May be NULL if the proxy has been destroyed.
	struct wl_proxy *wl;
	Janet send; // type is JANET_FUNCTION
};

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
	janet_mark(j->send);
	return 0;
}

JANET_FN(jwl_display_disconnect,
		"(wl/display/disconnect display)",
		"wl_display_disconnect") {
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
		"(wl/display/roundtrip display)",
		"wl_display_roundtrip") {
	janet_fixarity(argc, 1);
	struct jwl_proxy *j = janet_getabstract(argv, 0, &jwl_proxy_type);
	if (j->wl == NULL) {
		janet_panic("proxy invalid");
	}
	wl_display_roundtrip((struct wl_display *)j->wl);
	return janet_wrap_nil();
}

JanetMethod jwl_display_methods[] = {
	{"disconnect", jwl_display_disconnect },
	{"roundtrip", jwl_display_roundtrip },
	{NULL, NULL},
};

static void jwl_check_interface(JanetTable *interfaces, Janet name);

static void jwl_check_message(JanetTable *interfaces, Janet jmessage) {
	if (!janet_checktype(jmessage, JANET_STRUCT)) {
		janet_panicf("expected message struct, got %v", jmessage);
	}
	JanetStruct message = janet_unwrap_struct(jmessage);

	Janet jname = janet_struct_get(message, janet_ckeywordv("name"));
	if (!janet_checktype(jname, JANET_STRING)) {
		janet_panicf("expected string message :name, got %v", jname);
	}

	Janet jsignature = janet_struct_get(message, janet_ckeywordv("signature"));
	if (!janet_checktype(jsignature, JANET_STRING)) {
		janet_panicf("expected string message :signature, got %v", jsignature);
	}
	const uint8_t *signature = janet_unwrap_string(jsignature);
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
			janet_panicf("invalid message signature %v", jsignature);
		}
	}

	Janet jtypes = janet_struct_get(message, janet_ckeywordv("types"));
	if (!janet_checktype(jtypes, JANET_TUPLE)) {
		janet_panicf("expected tuple message :types, got %v", jtypes);
	}
	JanetTuple types = janet_unwrap_tuple(jtypes);
	for (int32_t i = 0; i < janet_tuple_length(types); i++) {
		if (!janet_checktype(types[i], JANET_NIL)) {
			jwl_check_interface(interfaces, types[i]);
		}
	}
}

static void jwl_check_interface(JanetTable *interfaces, Janet name) {
	Janet jinterface = janet_table_get(interfaces, name);
	if (!janet_checktype(jinterface, JANET_STRUCT)) {
		janet_panicf("expected interface struct, got %v", jinterface);
	}
	JanetStruct interface = janet_unwrap_struct(jinterface);

	Janet name_field = janet_struct_get(interface, janet_ckeywordv("name"));
	if (!janet_equals(name, name_field)) {
		janet_panicf("invalid interface name: %v", name_field);
	}

	// Handle cyclical references
	Janet existing = janet_table_get(&wl_interfaces, name);
	if (janet_truthy(existing)) {
		return;
	}
	janet_table_put(&wl_interfaces, name, janet_wrap_true());

	Janet jversion = janet_struct_get(interface, janet_ckeywordv("version"));
	if (!janet_checkuint(jversion)) {
		janet_panicf("expected u32 interface :version, got %v", jversion);
	}

	Janet jrequests = janet_struct_get(interface, janet_ckeywordv("requests"));
	if (!janet_checktype(jrequests, JANET_TUPLE)) {
		janet_panicf("expected tuple interface :requests, got %v", jrequests);
	}
	JanetTuple requests = janet_unwrap_tuple(jrequests);
	for (int32_t i = 0; i < janet_tuple_length(requests); i++) {
		jwl_check_message(interfaces, requests[i]);
	}

	Janet jevents = janet_struct_get(interface, janet_ckeywordv("events"));
	if (!janet_checktype(jevents, JANET_TUPLE)) {
		janet_panicf("expected tuple interface :events, got %v", jevents);
	}
	JanetTuple events = janet_unwrap_tuple(jevents);
	for (int32_t i = 0; i < janet_tuple_length(events); i++) {
		jwl_check_message(interfaces, events[i]);
	}

	Janet jsend = janet_struct_get(interface, janet_ckeywordv("send"));
	if (!janet_checktype(jsend, JANET_FUNCTION)) {
		janet_panicf("expected function interface :send, got %v", jsend);
	}
}

static struct wl_interface *jwl_get_wl_interface_unchecked(JanetTable *interfaces, Janet name);

static struct wl_message jwl_get_wl_message_unchecked(JanetTable *interfaces, Janet jmessage) {
	JanetStruct message = janet_unwrap_struct(jmessage);
	struct wl_message wl;

	Janet jname = janet_struct_get(message, janet_ckeywordv("name"));
	wl.name = strdup((char *)janet_unwrap_string(jname));
	if (wl.name == NULL) {
		JANET_OUT_OF_MEMORY;
	}

	Janet jsignature = janet_struct_get(message, janet_ckeywordv("signature"));
	wl.signature = strdup((char *)janet_unwrap_string(jsignature));
	if (wl.signature == NULL) {
		JANET_OUT_OF_MEMORY;
	}

	Janet jtypes = janet_struct_get(message, janet_ckeywordv("types"));
	JanetTuple types = janet_unwrap_tuple(jtypes);

	wl.types = malloc(janet_tuple_length(types) * sizeof(struct wl_interface *));
	if (wl.types == NULL) {
		JANET_OUT_OF_MEMORY;
	}
	for (int32_t i = 0; i < janet_tuple_length(types); i++) {
		if (janet_checktype(types[i], JANET_NIL)) {
			wl.types[i] = NULL;
		} else {
			wl.types[i] = jwl_get_wl_interface_unchecked(interfaces, types[i]);
		}
	}

	return wl;
}

static struct wl_interface *jwl_get_wl_interface_unchecked(JanetTable *interfaces,
		Janet name) {
	JanetStruct interface = janet_unwrap_struct(janet_table_get(interfaces, name));

	Janet existing = janet_table_get(&wl_interfaces, name);
	if (janet_checktype(existing, JANET_POINTER)) {
		return janet_unwrap_pointer(existing);
	}

	struct wl_interface *wl = malloc(sizeof(struct wl_interface));
	if (wl == NULL) {
		JANET_OUT_OF_MEMORY;
	}
	janet_table_put(&wl_interfaces, name, janet_wrap_pointer(wl));

	wl->name = strdup((char *)janet_unwrap_string(name));
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
		((struct wl_message *)wl->methods)[i] = jwl_get_wl_message_unchecked(interfaces, requests[i]);
	}

	JanetTuple events = janet_unwrap_tuple(janet_struct_get(interface, janet_ckeywordv("events")));
	wl->event_count = janet_tuple_length(events);
	wl->events = malloc(janet_tuple_length(events) * sizeof(struct wl_message));
	if (wl->events == NULL) {
		JANET_OUT_OF_MEMORY;
	}
	for (int32_t i = 0; i < janet_tuple_length(events); i++) {
		((struct wl_message *)wl->events)[i] = jwl_get_wl_message_unchecked(interfaces, events[i]);
	}

	return wl;
}

// interface is a struct of the form:
// {:name "wl_foo"
//  :version 4
//  :requests [{:name "create"
//              :signature "2u?o"
//              :types [nil, interface]}]
//  :events []}
static const struct wl_interface *jwl_get_wl_interface(JanetTable *interfaces, Janet name) {
	Janet existing = janet_table_get(&wl_interfaces, name);
	if (janet_checktype(existing, JANET_POINTER)) {
		return janet_unwrap_pointer(existing);
	}
	janet_table_put(&wl_interfaces, name, janet_wrap_true());

	jwl_check_interface(interfaces, name);

	return jwl_get_wl_interface_unchecked(interfaces, name);
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
		"(wl/proxy/send-raw proxy interfaces opcode interface version flags args)",
		"Calls wl_proxy_marshal_array_flags() internally") {
	janet_fixarity(argc, 7);
	struct jwl_proxy *j = janet_getabstract(argv, 0, &jwl_proxy_type);
	if (j->wl == NULL) {
		janet_panic("proxy invalid");
	}
	JanetTable *interfaces = janet_gettable(argv, 1);
	uint32_t opcode = janet_getuinteger(argv, 2);
	janet_optcstring(argv, argc, 3, NULL);
	Janet interface_name = argv[3];
	uint32_t version = janet_getuinteger(argv, 4);
	JanetStruct flags = janet_getstruct(argv, 5);
	JanetTuple args = janet_gettuple(argv, 6);

	const struct wl_interface *wl_interface = NULL;
	Janet send = janet_wrap_nil();
	if (!janet_checktype(interface_name, JANET_NIL)) {
		wl_interface = jwl_get_wl_interface(interfaces, interface_name);
		JanetStruct interface = janet_unwrap_struct(janet_table_get(interfaces, interface_name));
		send = janet_struct_get(interface, janet_ckeywordv("send"));
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
		struct jwl_proxy *new_j = janet_abstract(&jwl_proxy_type, sizeof(struct jwl_proxy));
		new_j->wl = new_wl;
		new_j->send = send;
		wl_proxy_set_user_data(new_j->wl, new_j);
		return janet_wrap_abstract(new_j);
	}
}

JanetMethod jwl_proxy_methods[] = {
	{"send-raw", jwl_proxy_send_raw},
	{NULL, NULL},
};

static int jwl_proxy_get(void *p, Janet key, Janet *out) {
	struct jwl_proxy *j = p;
	if (!janet_checktype(key, JANET_KEYWORD)) {
		return 0;
	}

	JanetKeyword method = janet_unwrap_keyword(key);
	if (janet_cstrcmp(method, "send") == 0) {
		*out = j->send;
		return 1;
	}

	if (janet_getmethod(method, jwl_proxy_methods, out)) {
		return 1;
	}

	if (j->wl == NULL) {
		janet_panic("proxy invalid");
	}
	if (wl_proxy_get_interface(j->wl) == &wl_display_interface) {
		return janet_getmethod(method, jwl_display_methods, out);
	} else {
		return 0;

	}
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

JANET_FN(jwl_display_connect,
		"(wl/display/connect-raw interfaces &opt name)",
		"wl_display_connect") {
	janet_arity(argc, 1, 2);
	JanetTable *interfaces = janet_gettable(argv, 0);
	const char *name = janet_optcstring(argv, argc, 1, NULL);

	(void)jwl_get_wl_interface(interfaces, janet_cstringv("wl_display"));
	JanetStruct interface = janet_unwrap_struct(
		janet_table_get(interfaces, janet_cstringv("wl_display")));
	Janet send = janet_struct_get(interface, janet_ckeywordv("send"));

	struct wl_display *wl = wl_display_connect(name);
	if (!wl) {
		janet_panicf("unable to connect to wayland server: %s", strerror(errno));
	}

	struct jwl_proxy *j = janet_abstract(&jwl_proxy_type, sizeof(struct jwl_proxy));
	j->wl = (struct wl_proxy *)wl;
	j->send = send;
	wl_proxy_set_user_data(j->wl, j);

	return janet_wrap_abstract(j);
}

JANET_MODULE_ENTRY(JanetTable *env) {
	janet_table_init_raw(&wl_interfaces, 0);
	JanetRegExt cfuns[] = {
		JANET_REG("display/connect-raw", jwl_display_connect),
		JANET_REG_END,
	};
	janet_cfuns_ext(env, "wayland-native", cfuns);
}
