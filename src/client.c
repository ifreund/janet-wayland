#include <assert.h>
#include <errno.h>

#include <janet.h>
#include <wayland-client-core.h>
#include <wayland-client-protocol.h>

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
		janet_panic("display already disconnected/invalid");
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
		janet_panic("display already disconnected/invalid");
	}
	wl_display_roundtrip((struct wl_display *)j->wl);
	return janet_wrap_nil();
}

JanetMethod jwl_display_methods[] = {
	{"disconnect", jwl_display_disconnect },
	{"roundtrip", jwl_display_roundtrip },
	{NULL, NULL},
};

static int jwl_proxy_get(void *p, Janet key, Janet *out) {
	(void)p;
	if (!janet_checktype(key, JANET_KEYWORD)) {
		return 0;
	}
	// XXX not all proxys have display methods
	return janet_getmethod(janet_unwrap_keyword(key), jwl_display_methods, out);
}

static void jwl_proxy_tostring(void *p, JanetBuffer *buffer) {
	struct jwl_proxy *j = p;
	if (j->wl == NULL) {
		janet_buffer_push_cstring(buffer, "invalid");
	} else {
		janet_buffer_push_cstring(buffer, wl_proxy_get_class(j->wl));
		janet_buffer_push_u8(buffer, '#');
		char id[32];
		snprintf(id, sizeof(id), "%" PRIu32, wl_proxy_get_id(j->wl));
		janet_buffer_push_cstring(buffer, id);
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
	JanetRegExt cfuns[] = {
		JANET_REG("display/connect", jwl_display_connect),
		JANET_REG_END,
	};
	janet_cfuns_ext(env, "wl", cfuns);
}
