//
// mod_auth_ticket - Authentication based on signed cookie
//
// This module protects webpage from clients without valid
// cookie. By redirecting not-yet-valid clients to certain
// "logon page", you can protect any webapp without adding
// any auth code to webapp itself.
//
// Unlike mod_authcookie for Apache, this DOES NOT work
// with mod_auth_* modules due to lighttpd limitation (there's
// no way to turn 401 response into page redirection).
// This module solely relies on external "logon page" for
// authentication, and expect it to provide a valid cookie as a
// ticket for authenticated access.
//

#include "first.h"

#include <string.h>
#include <stdlib.h>

#include "base.h"
#include "plugin.h"
#include "log.h"
#include "md5.h"
#include "base64.h"
#include "rand.h"
#include "http_auth.h"
#include "http_header.h"
#include "splaytree.h"

/**********************************************************************
 * data strutures
 **********************************************************************/

// module configuration
typedef struct {
    buffer *name;    // cookie name to extract auth info
    int override;    // how to handle incoming Auth header
    int timeout;     // life duration of last-stage auth token
    buffer *authurl; // page to go when unauthorized
    buffer *key;     // key for cookie verification
    buffer *options; // options for last-stage auth token cookie
} plugin_config;

// top-level module structure
typedef struct {
    PLUGIN_DATA;
    plugin_config **config;
    plugin_config   conf;
    splay_tree *sptree;
    int timeout_max;
} plugin_data;

/**********************************************************************
 * supporting functions
 **********************************************************************/

//
// helper to generate "configuration in current context".
//
static plugin_config *
merge_config(server *srv, connection *con, plugin_data *pd) {
#define PATCH(x) pd->conf.x = pc->x
#define MATCH(k) if (buffer_is_equal_string(du->key, CONST_STR_LEN(k)))
#define MERGE(k, x) MATCH(k) PATCH(x)

    size_t i, j;
    plugin_config *pc = pd->config[0]; // start from global context

    // load initial config in global context
    PATCH(name);
    PATCH(override);
    PATCH(authurl);
    PATCH(key);
    PATCH(timeout);
    PATCH(options);

    // merge config from sub-contexts
    for (i = 1; i < srv->config_context->used; i++) {
        data_config *dc = (data_config *)srv->config_context->data[i];

        // condition didn't match
        if (! config_check_cond(srv, con, dc)) continue;

        // merge config
        pc = pd->config[i];
        for (j = 0; j < dc->value->used; j++) {
            data_unset *du = dc->value->data[j];

            // describe your merge-policy here...
            MERGE("auth-ticket.name", name);
            MERGE("auth-ticket.override", override);
            MERGE("auth-ticket.authurl", authurl);
            MERGE("auth-ticket.key", key);
            MERGE("auth-ticket.timeout", timeout);
            MERGE("auth-ticket.options", options);
        }
    }
    return &(pd->conf);
#undef PATCH
#undef MATCH
#undef MERGE
}

typedef struct {
    int token[4];
    buffer *field;
    time_t ts;
} auth_ticket_sptree_node_t;

static auth_ticket_sptree_node_t * auth_ticket_sptree_node_init(void) {
    auth_ticket_sptree_node_t *spn = calloc(1, sizeof(*spn));
    force_assert(NULL != spn);
    spn->field = buffer_init();
    return spn;
}

static void auth_ticket_sptree_node_free(void *data) {
    auth_ticket_sptree_node_t *spn = data;
    if (!spn) return;
    buffer_free(spn->field);
    free(spn);
}

static void auth_ticket_sptree_free(splay_tree *sptree) {
    while (sptree) {
        auth_ticket_sptree_node_free(sptree->data);
        sptree = splaytree_delete(sptree, sptree->key);
    }
}

static void auth_ticket_sptree_node_insert(plugin_data *pd, int randtok[4], time_t ts, const char *authinfo, size_t authlen) {
    /* strip highest bit (for splaytree) */
    int key = randtok[0] & (int)~(((uint32_t)1) << 31);
    auth_ticket_sptree_node_t *spn;
    pd->sptree = splaytree_splay(pd->sptree, key);
    if (!pd->sptree || pd->sptree->key != key) {
        spn = auth_ticket_sptree_node_init();
        pd->sptree = splaytree_insert(pd->sptree, key, spn);
    }
    else {
        /*(silently replace if hash collision; invalidate existing token)*/
        spn = pd->sptree->data;
    }
    spn->ts = ts;
    memcpy(spn->token, randtok, sizeof(spn->token));
    buffer_copy_string_len(spn->field, authinfo, authlen);
}

//
// fills (appends) given buffer with "current" URL.
//
static buffer *
self_url(connection *con, buffer *url, buffer_encoding_t enc) {
    buffer_append_string_encoded(url, CONST_BUF_LEN(con->uri.scheme), enc);
    buffer_append_string_encoded(url, CONST_STR_LEN("://"), enc);
    buffer_append_string_encoded(url, CONST_BUF_LEN(con->uri.authority), enc);
    buffer_append_string_encoded(url, CONST_BUF_LEN(con->request.orig_uri),enc);
    return url;
}

//
// Generates appropriate response depending on policy.
//
static handler_t
endauth(server *srv, connection *con, plugin_config *pc) {
    buffer *url = srv->tmp_buf;

    // pass through if no redirect target is specified
    if (buffer_is_empty(pc->authurl)) {
        return HANDLER_GO_ON;
    }

    // prepare redirection header
    buffer_copy_buffer(url, pc->authurl);
    buffer_append_string_len(url, strchr(url->ptr, '?') ? "&url=" : "?url=", 5);
    self_url(con, url, ENCODING_REL_URI);
    http_header_response_set(con, HTTP_HEADER_LOCATION,
                             CONST_STR_LEN("Location"),
                             CONST_BUF_LEN(url));

    // prepare response
    con->http_status = 307;
    con->mode = DIRECT;
    con->file_finished = 1;

    return HANDLER_FINISHED;
}

#if 0
// XOR-based decryption
// This is not used in this module - it is only provided as an
// example of supported encryption.
static char * __attribute__((unused))
encrypt(buffer *buf, uint8_t *key, int keylen) {
    char * const s = buf->ptr;
    for (size_t i = 0, used = buffer_string_length(buf); i < used; i++) {
        s[i] ^= (i > 0 ? s[i - 1] : 0) ^ key[i % keylen];
    }
    return s;
}
#endif

// XOR-based encryption
static int
decrypt(unsigned char * const s, size_t slen, uint8_t *key, int keylen) {
    for (int i = (int)slen; i >= 0; --i) {
        s[i] ^= (i > 0 ? s[i - 1] : 0) ^ key[i % keylen];
    }
    return 0;
}

//
// set environment with auth info
//
static void
auth_ticket_setenv(server *srv, connection *con,
                   const char *authinfo, size_t authlen) {
    // update REMOTE_USER
    // (future potential optimization would be to store decoded username
    //  as additional field in auth_ticket_sptree_node_t)
    char *colon;
    buffer *field = srv->tmp_buf;
    buffer_clear(field);
    buffer_append_base64_decode(field, authinfo, authlen, BASE64_STANDARD);
    colon = strchr(field->ptr, ':');
    if (colon) buffer_string_set_length(field, colon - field->ptr);
    http_auth_setenv(con, CONST_BUF_LEN(field),
                          CONST_STR_LEN("mod_authn_ticket"));

  #if 0 /* (no longer needed if mod_auth "extern" auth mode is used) */
    // inject Basic Auth header
    buffer_copy_string_len(field, CONST_STR_LEN("Basic "));
    buffer_append_string_len(field, authinfo, authlen);
    http_header_request_set(con, HTTP_HEADER_AUTHORIZATION,
                            CONST_STR_LEN("Authorization"),
                            CONST_BUF_LEN(field));
  #endif
}

//
// update header using (verified) authentication info.
//
static void
update_header(server *srv, connection *con,
              plugin_data *pd, plugin_config *pc,
              const char *authinfo, size_t authlen) {
    buffer *field = srv->tmp_buf;

    // generate random token
    int randtok[4];
    li_rand_pseudo_bytes((unsigned char *)randtok, sizeof(randtok));

    auth_ticket_sptree_node_insert(pd, randtok, srv->cur_ts, authinfo, authlen);
    auth_ticket_setenv(srv, con, authinfo, authlen);

    // insert opaque auth token
    buffer_copy_buffer(field, pc->name);
    buffer_append_string_len(field, CONST_STR_LEN("=token:"));
    buffer_append_string_encoded_hex_lc(field,(char *)randtok,sizeof(randtok));
    buffer_append_string_buffer(field, pc->options);
    http_header_response_insert(con, HTTP_HEADER_SET_COOKIE,
                                CONST_STR_LEN("Set-Cookie"),
                                CONST_BUF_LEN(field));
}

static int
li_hex2bin(uint8_t *bin, size_t sz, const char *s, size_t slen) {
    const unsigned char *h = (const unsigned char *)s;
    if ((slen & 1) || (slen >> 1) > sz) return -1;
    for (size_t i = 0; i < slen; i+=2) {
        unsigned char hi = hex2int(h[i]);
        unsigned char lo = hex2int(h[i+1]);
        bin[i>>1] = (hi << 4) | lo;
        if (0xFF == hi || 0xFF == lo) return -1;
    }
    return 0;
}

//
// Handle token given in cookie.
//
// Expected Cookie Format:
//   <name>=token:<random-token-to-be-verified>
//
static auth_ticket_sptree_node_t *
token_lookup(plugin_data *pd, const char *token) {

    size_t len = strlen(token);
    int randtok[4]; /* decode hexstring into bytes */
    if (0 == li_hex2bin((uint8_t *)randtok, sizeof(randtok), token, len)) {
        /* strip highest bit (for splaytree) */
        int key = randtok[0] & (int)~(((uint32_t)1) << 31);
        pd->sptree = splaytree_splay(pd->sptree, key);
        if (pd->sptree && pd->sptree->key == key) {
            auth_ticket_sptree_node_t *spn = pd->sptree->data;
            if (0 == memcmp(spn->token, randtok, sizeof(randtok))) {
                return spn;
            }
        }
    }

    return NULL;
}

//
// Check for redirected auth request in cookie.
//
// Expected Cookie Format:
//   <name>=crypt:<hash>:<data>
//
//   hash    = hex(MD5(key + timesegment + data))
//   data    = hex(encrypt(MD5(timesegment + key), payload))
//   payload = base64(username + ":" + password)
//
static handler_t
handle_crypt(server *srv, connection *con,
             plugin_data *pd, plugin_config *pc, const char *line) {
    li_MD5_CTX ctx;
    uint8_t hash[16];
    uint8_t token[16];
    char tmp[LI_ITOSTRING_LENGTH];
    size_t len;
    char authinfo[1024];
    time_t t1, t0 = srv->cur_ts;

    // Check for existence of data part
    const char *data = strchr(line, ':');
    if (! data) return endauth(srv, con, pc);
    if (0 != li_hex2bin(token, sizeof(token), line, data - line)) {
        return endauth(srv, con, pc);
    }
    ++data;
    len = strlen(data);

    // Verify signature.
    // Also, find time segment when this auth request was encrypted.
    for (t1 = t0 - (t0 % 5); t0 - t1 < 10; t1 -= 5) {
        // compute hash for this time segment
        li_itostrn(tmp, sizeof(tmp), t1);
        li_MD5_Init(&ctx);
        li_MD5_Update(&ctx, CONST_BUF_LEN(pc->key));
        li_MD5_Update(&ctx, (unsigned char *)tmp, strlen(tmp));
        li_MD5_Update(&ctx, (unsigned char *)data, len);
        li_MD5_Final(hash, &ctx);

        // verify by comparing hash
        if (0 == memcmp(hash, token, sizeof(hash))) {
            break; // hash verified and time segment found
        }
    }

    // Has this found time segment expired?
    if (! (t0 - t1 < 10)) {
        return endauth(srv, con, pc);
    }

    // compute temporal encryption key (= MD5(t1, key))
    li_itostrn(tmp, sizeof(tmp), t1);
    li_MD5_Init(&ctx);
    li_MD5_Update(&ctx, tmp, strlen(tmp));
    li_MD5_Update(&ctx, CONST_BUF_LEN(pc->key));
    li_MD5_Final(hash, &ctx);

    // decode hexstring into bytes
    if (0 != li_hex2bin((uint8_t *)authinfo, sizeof(authinfo), data, len)) {
        return endauth(srv, con, pc);
    }
    // (finished using char *line and char *data;
    //  srv->tmp_buf can safely be reused in update_header())

    // decrypt
    len >>= 1;
    if (decrypt((unsigned char *)authinfo, len, hash, sizeof(hash)) != 0) {
        return endauth(srv, con, pc);
    }

    {   // sanity check - result should be base64-encoded authinfo
        buffer *b = srv->tmp_buf;
        buffer_clear(b);
        if (!buffer_append_base64_decode(b, authinfo, len, BASE64_STANDARD)) {
            return endauth(srv, con, pc);
        }
    }

    // update header using decrypted authinfo
    update_header(srv, con, pd, pc, authinfo, len);

    return HANDLER_GO_ON;
}

static handler_t
module_cookie_check(server *srv, connection *con, plugin_data *pd, plugin_config *pc) {
    buffer *b;
    char *cs;       // pointer to (some part of) <AuthName> key

    // decide how to handle incoming Auth header
    b = http_header_request_get(con, HTTP_HEADER_AUTHORIZATION,
                                CONST_STR_LEN("Authorization"));
    if (b != NULL) {
        switch (pc->override) {
        case 0: return HANDLER_GO_ON;   // just use it if supplied
        case 1: break;                  // use CookieAuth if exists
        case 2:
        default: http_header_request_unset(con, HTTP_HEADER_AUTHORIZATION,
                                           CONST_STR_LEN("Authorization"));
                 break;                 // use CookieAuth only
        }
    }

    // check for cookie
    b = http_header_request_get(con,HTTP_HEADER_COOKIE,CONST_STR_LEN("Cookie"));
    if (b == NULL) return endauth(srv, con, pc);

    // check for "<AuthName>=" entry in a cookie
    for (cs = b->ptr; (cs = strstr(cs, pc->name->ptr)) != NULL; ) {
        // check if found entry matches exactly for "KEY=" part.
        cs += buffer_string_length(pc->name);  // jump to the end of "KEY" part
        while (*cs == ' ' || *cs == '\t') ++cs; // whitespace can be skipped

        // break forward if this was an exact match
        if (*cs++ == '=') break;
    }
    if (! cs) return endauth(srv, con, pc); // not found - rejecting

    // unescape payload
    {
        char *eot = strchr(cs, ';');
        if (NULL == eot) eot = b->ptr + buffer_string_length(b);
        buffer_copy_string_len(srv->tmp_buf, cs, (size_t)(eot - cs));
    }
    buffer_urldecode_path(srv->tmp_buf);
    cs = srv->tmp_buf->ptr;

    if (buffer_string_length(srv->tmp_buf) > 6) {
        if (0 == memcmp(cs, "token:", 6)) {
            // Allow access if client already has an "authorized" token.
            auth_ticket_sptree_node_t *spn = token_lookup(pd, cs + 6);
            if (NULL != spn && srv->cur_ts - spn->ts <= pc->timeout) {
                auth_ticket_setenv(srv, con, CONST_BUF_LEN(spn->field));
                return HANDLER_GO_ON;
            }
        }
        else if (0 == memcmp(cs, "crypt:", 6)) {
            // Verify "non-authorized" CookieAuth request in encrypted format.
            // Once verified, give out authorized token ("token:..." cookie).
            return handle_crypt(srv, con, pd, pc, cs + 6);
        }
    }

    /* unrecognized cookie auth format */
    return endauth(srv, con, pc);
}

/**********************************************************************
 * module interface
 **********************************************************************/

INIT_FUNC(module_init) {
    return calloc(1, sizeof(plugin_data));
}

FREE_FUNC(module_free) {
    plugin_data *pd = p_d;

    if (! pd) return HANDLER_GO_ON;

    // Free plugin data
    auth_ticket_sptree_free(pd->sptree);

    // Free configuration data.
    // This must be done for each context.
    if (pd->config) {
        size_t i;
        for (i = 0; i < srv->config_context->used; i++) {
            plugin_config *pc = pd->config[i];
            if (! pc) continue;

            // free configuration
            buffer_free(pc->name);
            buffer_free(pc->authurl);
            buffer_free(pc->key);

            free(pc);
        }
        free(pd->config);
    }
    free(pd);

    return HANDLER_GO_ON;
}

//
// authorization handler
//
URIHANDLER_FUNC(module_uri_handler) {
    plugin_data   *pd = p_d;
    plugin_config *pc = merge_config(srv, con, pd);

    // skip if not enabled
    if (buffer_string_is_empty(pc->name)) return HANDLER_GO_ON;

    return module_cookie_check(srv, con, pd, pc);
}

SETDEFAULTS_FUNC(module_set_defaults) {
    plugin_data *pd = p_d;
    size_t i;

    config_values_t cv[] = {
        { "auth-ticket.name",
          NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },
        { "auth-ticket.override",
          NULL, T_CONFIG_INT,    T_CONFIG_SCOPE_CONNECTION },
        { "auth-ticket.authurl",
          NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },
        { "auth-ticket.key",
          NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },
        { "auth-ticket.timeout",
          NULL, T_CONFIG_INT,    T_CONFIG_SCOPE_CONNECTION },
        { "auth-ticket.options",
          NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },
        { NULL, NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
    };

    pd->config = calloc(1,
                        srv->config_context->used * sizeof(specific_config *));
    pd->timeout_max = -1;

    for (i = 0; i < srv->config_context->used; i++) {
        array *ca = ((data_config *)srv->config_context->data[i])->value;
        plugin_config *pc;

        pc = pd->config[i] = calloc(1, sizeof(plugin_config));
        pc->name     = buffer_init();
        pc->override = 2;
        pc->authurl  = buffer_init();
        pc->key      = buffer_init();
        pc->timeout  = -1;
        pc->options  = buffer_init();

        cv[0].destination = pc->name;
        cv[1].destination = &(pc->override);
        cv[2].destination = pc->authurl;
        cv[3].destination = pc->key;
        cv[4].destination = &(pc->timeout);
        cv[5].destination = pc->options;

        if (0 != config_insert_values_global(srv, ca, cv, i == 0 ? T_CONFIG_SCOPE_SERVER : T_CONFIG_SCOPE_CONNECTION)) {
            return HANDLER_ERROR;
        }
        if (!buffer_string_is_empty(pc->options)) {
            buffer_copy_buffer(srv->tmp_buf, pc->options);
            buffer_copy_string_len(pc->options, CONST_STR_LEN("; "));
            buffer_append_string_buffer(pc->options, srv->tmp_buf);
        }
        if (pc->timeout == -1) {
            pc->timeout = 86400;
            if (pd->timeout_max == -1 && !buffer_string_is_empty(pc->name)) {
                pd->timeout_max = 86400;
            }
        }
        else {
            if (pd->timeout_max < pc->timeout) {
                pd->timeout_max = pc->timeout;
            }
        }
    }

    if (pd->timeout_max == -1) {
        pd->timeout_max = 86400;
    }

    return HANDLER_GO_ON;
}

/**
 * remove expired nodes from splaytree
 *
 * walk tree to collect keys of expired nodes,
 * then remove expired nodes in second loop
 */

static void sptree_tag_old_entries(const splay_tree * const t, const time_t expire, int * const keys, size_t * const ndx) {
    auth_ticket_sptree_node_t *spn;

    if (t->left)  sptree_tag_old_entries(t->left, expire, keys, ndx);
    if (t->right) sptree_tag_old_entries(t->right, expire, keys, ndx);

    spn = t->data;
    if (spn->ts < expire) keys[(*ndx)++] = t->key;
}

static void sptree_expire_nodes(plugin_data * const pd, const time_t expire) {
    /*assert(pd->sptree);*/
    size_t max_ndx = 0;
    int * const keys = calloc(1, sizeof(int) * pd->sptree->size);
    force_assert(NULL != keys);

    sptree_tag_old_entries(pd->sptree, expire, keys, &max_ndx);

    for (size_t i = 0; i < max_ndx; ++i) {
        pd->sptree = splaytree_splay(pd->sptree, keys[i]);
        auth_ticket_sptree_node_free(pd->sptree->data);
        pd->sptree = splaytree_delete(pd->sptree, keys[i]);
    }

    free(keys);
}

TRIGGER_FUNC(module_trigger) {
    plugin_data * const pd = p_d;

    /* (scan splaytree only once every 64 seconds and not empty) */
    if (pd->sptree && 0 == (srv->cur_ts & 0x3f))
        sptree_expire_nodes(pd, srv->cur_ts - pd->timeout_max);

    return 0;
}

int mod_auth_ticket_plugin_init(plugin *p);
int mod_auth_ticket_plugin_init(plugin *p) {
    p->version          = LIGHTTPD_VERSION_ID;
    p->name             = buffer_init_string("auth_ticket");
    p->init             = module_init;
    p->set_defaults     = module_set_defaults;
    p->cleanup          = module_free;
    p->handle_trigger   = module_trigger;
    p->handle_uri_clean = module_uri_handler;
    p->data             = NULL;

    return 0;
}
