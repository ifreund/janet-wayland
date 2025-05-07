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

JanetTable interfaces;

const JanetAbstractType jwl_proxy_type;
struct jwl_proxy {
	// May be NULL if the proxy has been destroyed.
	struct wl_proxy *wl;
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

static void jwl_check_interface(Janet jinterface);
static void jwl_check_message(Janet jmessage) {
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
			jwl_check_interface(types[i]);
		}
	}
}

static void jwl_check_interface(Janet jinterface) {
	if (!janet_checktype(jinterface, JANET_STRUCT)) {
		janet_panicf("expected interface struct, got %v", jinterface);
	}
	JanetStruct interface = janet_unwrap_struct(jinterface);

	Janet jname = janet_struct_get(interface, janet_ckeywordv("name"));
	if (!janet_checktype(jname, JANET_STRING)) {
		janet_panicf("expected string interface :name, got %v", jname);
	}

	// Handle cyclical references
	Janet existing = janet_table_get(&interfaces, jname);
	if (janet_truthy(existing)) {
		return;
	}
	janet_table_put(&interfaces, jname, janet_wrap_true());

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
		jwl_check_message(requests[i]);
	}

	Janet jevents = janet_struct_get(interface, janet_ckeywordv("events"));
	if (!janet_checktype(jevents, JANET_TUPLE)) {
		janet_panicf("expected tuple interface :events, got %v", jevents);
	}
	JanetTuple events = janet_unwrap_tuple(jevents);
	for (int32_t i = 0; i < janet_tuple_length(events); i++) {
		jwl_check_message(events[i]);
	}
}

static struct wl_interface *jwl_get_interface_unchecked(Janet jinterface);

static struct wl_message jwl_get_message_unchecked(Janet jmessage) {
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
		    wl.types[i] = jwl_get_interface_unchecked(types[i]);
		}
	}

    return wl;
}

static struct wl_interface *jwl_get_interface_unchecked(Janet jinterface) {
    JanetStruct interface = janet_unwrap_struct(jinterface);
	Janet jname = janet_struct_get(interface, janet_ckeywordv("name"));

	Janet existing = janet_table_get(&interfaces, jname);
	if (janet_checktype(existing, JANET_POINTER)) {
		return janet_unwrap_pointer(existing);
	}

	struct wl_interface *wl = malloc(sizeof(struct wl_interface));
	if (wl == NULL) {
		JANET_OUT_OF_MEMORY;
	}
	janet_table_put(&interfaces, jname, janet_wrap_pointer(wl));

	wl->name = strdup((char *)janet_unwrap_string(jname));
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
	    ((struct wl_message *)wl->methods)[i] = jwl_get_message_unchecked(requests[i]);
	}
	
	JanetTuple events = janet_unwrap_tuple(janet_struct_get(interface, janet_ckeywordv("events")));
	wl->event_count = janet_tuple_length(events);
	wl->events = malloc(janet_tuple_length(events) * sizeof(struct wl_message));
	if (wl->events == NULL) {
		JANET_OUT_OF_MEMORY;
	}
	for (int32_t i = 0; i < janet_tuple_length(events); i++) {
	    ((struct wl_message *)wl->events)[i] = jwl_get_message_unchecked(events[i]);
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
static const struct wl_interface *jwl_get_interface(
		const Janet *argv, int32_t argc, int32_t n) {
	JanetStruct interface = janet_optstruct(argv, argc, n, NULL);
	if (interface == NULL) {
		return NULL;
	}

	Janet jname = janet_struct_get(interface, janet_ckeywordv("name"));
	if (!janet_checktype(jname, JANET_STRING)) {
		janet_panicf("expected string interface :name, got %v", jname);
	}

	Janet existing = janet_table_get(&interfaces, jname);
	if (janet_checktype(existing, JANET_POINTER)) {
		return janet_unwrap_pointer(existing);
	}
	janet_table_put(&interfaces, jname, janet_wrap_true());

	jwl_check_interface(argv[n]);
    
    return jwl_get_interface_unchecked(argv[n]);
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

JANET_FN(jwl_proxy_marshal,
	"(wl/proxy/marshal proxy opcode interface version flags args)",
	"wl_proxy_marshal_array_flags") {
	janet_fixarity(argc, 6);
	struct jwl_proxy *j = janet_getabstract(argv, 0, &jwl_proxy_type);
	if (j->wl == NULL) {
		janet_panic("proxy invalid");
	}
	uint32_t opcode = janet_getuinteger(argv, 1);
	const struct wl_interface *interface = jwl_get_interface(argv, argc, 2);
	uint32_t version = janet_getuinteger(argv, 3);
	JanetStruct flags = janet_getstruct(argv, 4);
	JanetTuple args = janet_gettuple(argv, 5);

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
				janet_panicf("expected (wl/proxy (%s)), got %v", expected->name, args[i]);
			}
			if (expected != NULL && wl_proxy_get_interface(o->wl) != expected) {
				janet_panicf("expected (wl/proxy (%s)), got %v", expected->name, args[i]);
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
		interface, version, wl_flags, wl_args);
	if (new_wl == NULL) {
		return janet_wrap_nil();
	} else {
		struct jwl_proxy *new_j = janet_abstract(&jwl_proxy_type, sizeof(struct jwl_proxy));
		new_j->wl = new_wl;
		wl_proxy_set_user_data(new_j->wl, new_j);
		return janet_wrap_abstract(new_j);
	}
}

JanetMethod jwl_proxy_methods[] = {
	{"marshal", jwl_proxy_marshal },
	{NULL, NULL},
};

static int jwl_proxy_get(void *p, Janet key, Janet *out) {
	(void)p;
	if (!janet_checktype(key, JANET_KEYWORD)) {
		return 0;
	}
	JanetKeyword method = janet_unwrap_keyword(key);
	if (janet_getmethod(method, jwl_proxy_methods, out)) {
	    return 1;
	}
	// XXX not all proxys have display methods
	return janet_getmethod(method, jwl_display_methods, out);
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
	jwl_proxy_gc, // gc
	NULL, // gcmark
	jwl_proxy_get, // get
	NULL, // put
	NULL, // marshal
	NULL, // unmarshal
	jwl_proxy_tostring, // tostring
	NULL, // compare
	NULL, // hash
	NULL, // next
	NULL, // call
	NULL, // length
	NULL, // bytes
};

JANET_FN(jwl_display_connect,
		"(wl/display/connect &opt name)",
		"wl_display_connect") {
	janet_arity(argc, 0, 1);
	const char *name = janet_optcstring(argv, argc, 0, NULL);

	struct wl_display *wl = wl_display_connect(name);
	if (!wl) {
		janet_panicf("unable to connect to wayland server: %s", strerror(errno));
	}

	struct jwl_proxy *j = janet_abstract(&jwl_proxy_type, sizeof(struct jwl_proxy));
	j->wl = (struct wl_proxy *)wl;
	wl_proxy_set_user_data(j->wl, j);

	return janet_wrap_abstract(j);
}

JANET_MODULE_ENTRY(JanetTable *env) {
	janet_table_init_raw(&interfaces, 0);
	JanetRegExt cfuns[] = {
		JANET_REG("display/connect", jwl_display_connect),
		JANET_REG_END,
	};
	janet_cfuns_ext(env, "wl", cfuns);
}
