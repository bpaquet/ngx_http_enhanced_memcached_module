
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copytight (C) Bertrand Paquet
 */

#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <ngx_md5.h>

#ifndef NGX_UINT32_LEN
#define NGX_UINT32_LEN (NGX_INT32_LEN - 1)
#endif

typedef struct {
    ngx_http_upstream_conf_t   upstream;
    ngx_int_t                  key_index;
    ngx_int_t                  expire_index;
    ngx_int_t                  use_add_index;
    ngx_int_t                  key_namespace_index;
    ngx_flag_t                 hash_keys_with_md5;
    ngx_flag_t                 allow_put;
    ngx_flag_t                 allow_delete;
    ngx_flag_t                 stats;
    ngx_flag_t                 flush;
    ngx_flag_t                 flush_namespace;
    ngx_uint_t                 method_filter;
} ngx_http_enhanced_memcached_loc_conf_t;


typedef enum ngx_http_enhanced_memcached_key_status_e {
  UNKNOWN,
  WAIT_GET_NS,
  WAIT_INIT_NS,
  READY
} ngx_http_enhanced_memcached_key_status_t;

typedef struct {
    size_t                     rest;
    ngx_http_request_t        *request;
    ngx_str_t                  key;
    u_char                    *end;
    size_t                     end_len;
    ngx_http_enhanced_memcached_key_status_t key_status;
    ngx_str_t                  namespace_key;
    ngx_str_t                  namespace_value;
    ngx_int_t                 (*when_key_ready)(ngx_http_request_t *r);
} ngx_http_enhanced_memcached_ctx_t;


static ngx_int_t ngx_http_enhanced_memcached_compute_key(ngx_http_request_t *r);
static ngx_int_t ngx_http_enhanced_memcached_process_key(ngx_http_request_t *r);
static ngx_int_t ngx_http_enhanced_memcached_send_request_get(ngx_http_request_t *r);
static ngx_int_t ngx_http_enhanced_memcached_send_request_set(ngx_http_request_t *r);
static ngx_int_t ngx_http_enhanced_memcached_send_request_flush(ngx_http_request_t *r);
static ngx_int_t ngx_http_enhanced_memcached_send_request_stats(ngx_http_request_t *r);
static ngx_int_t ngx_http_enhanced_memcached_send_request_delete(ngx_http_request_t *r);
static ngx_int_t ngx_http_enhanced_memcached_send_request_incr_ns(ngx_http_request_t *r);
static ngx_int_t ngx_http_enhanced_memcached_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_enhanced_memcached_process_request_get(ngx_http_request_t *r);
static ngx_int_t ngx_http_enhanced_memcached_process_request_set(ngx_http_request_t *r);
static ngx_int_t ngx_http_enhanced_memcached_process_request_flush(ngx_http_request_t *r);
static ngx_int_t ngx_http_enhanced_memcached_process_request_stats(ngx_http_request_t *r);
static ngx_int_t ngx_http_enhanced_memcached_process_request_delete(ngx_http_request_t *r);
static ngx_int_t ngx_http_enhanced_memcached_process_request_incr_ns(ngx_http_request_t *r);
static ngx_int_t ngx_http_enhanced_memcached_filter_init(void *data);
static ngx_int_t ngx_http_enhanced_memcached_filter_chunked_init(void *data);
static ngx_int_t ngx_http_enhanced_memcached_filter(void *data, ssize_t bytes);
static ngx_int_t ngx_http_enhanced_memcached_filter_chunked(void *data, ssize_t bytes);
static void ngx_http_enhanced_memcached_abort_request(ngx_http_request_t *r);
static void ngx_http_enhanced_memcached_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc);

static ngx_int_t ngx_http_enhanced_memcached_init(ngx_conf_t *cf);
static void *ngx_http_enhanced_memcached_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_enhanced_memcached_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);

static char *ngx_http_enhanced_memcached_pass(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_command_t  ngx_http_enhanced_memcached_commands[] = {

    { ngx_string("enhanced_memcached_pass"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_enhanced_memcached_pass,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("enhanced_memcached_hash_keys_with_md5"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_enhanced_memcached_loc_conf_t, hash_keys_with_md5),
      NULL },

    { ngx_string("enhanced_memcached_allow_put"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_enhanced_memcached_loc_conf_t, allow_put),
      NULL },

    { ngx_string("enhanced_memcached_allow_delete"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_enhanced_memcached_loc_conf_t, allow_delete),
      NULL },

    { ngx_string("enhanced_memcached_stats"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_enhanced_memcached_loc_conf_t, stats),
      NULL },

    { ngx_string("enhanced_memcached_flush"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_enhanced_memcached_loc_conf_t, flush),
      NULL },

    { ngx_string("enhanced_memcached_flush_namespace"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_enhanced_memcached_loc_conf_t, flush_namespace),
      NULL },

    { ngx_string("enhanced_memcached_bind"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_upstream_bind_set_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_enhanced_memcached_loc_conf_t, upstream.local),
      NULL },

    { ngx_string("enhanced_memcached_connect_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_enhanced_memcached_loc_conf_t, upstream.connect_timeout),
      NULL },

    { ngx_string("enhanced_memcached_send_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_enhanced_memcached_loc_conf_t, upstream.send_timeout),
      NULL },

    { ngx_string("enhanced_memcached_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_enhanced_memcached_loc_conf_t, upstream.buffer_size),
      NULL },

    { ngx_string("enhanced_memcached_read_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_enhanced_memcached_loc_conf_t, upstream.read_timeout),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_enhanced_memcached_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_enhanced_memcached_init,               /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_enhanced_memcached_create_loc_conf,    /* create location configration */
    ngx_http_enhanced_memcached_merge_loc_conf      /* merge location configration */
};


ngx_module_t  ngx_http_enhanced_memcached_module = {
    NGX_MODULE_V1,
    &ngx_http_enhanced_memcached_module_ctx,        /* module context */
    ngx_http_enhanced_memcached_commands,           /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_str_t  ngx_http_enhanced_memcached_key = ngx_string("enhanced_memcached_key");
static ngx_str_t  ngx_http_enhanced_memcached_expire = ngx_string("enhanced_memcached_expire");
static ngx_str_t  ngx_http_enhanced_memcached_use_add = ngx_string("enhanced_memcached_use_add");
static ngx_str_t  ngx_http_enhanced_memcached_key_namespace = ngx_string("enhanced_memcached_key_namespace");

#define NGX_HTTP_ENHANCED_MEMCACHED_STATS   (sizeof(ngx_http_enhanced_memcached_stats) - 1)
static u_char  ngx_http_enhanced_memcached_stats[] = "STAT ";

#define NGX_HTTP_ENHANCED_MEMCACHED_END   (sizeof(ngx_http_enhanced_memcached_end) - 1)
static u_char  ngx_http_enhanced_memcached_end[] = CRLF "END" CRLF;

#define NGX_HTTP_ENHANCED_MEMCACHED_CRLF   (sizeof(ngx_http_enhanced_memcached_crlf) - 1)
static u_char  ngx_http_enhanced_memcached_crlf[] = CRLF;

#define NGX_HTTP_ENHANCED_MEMCACHED_EXTRACT_HEADERS  (sizeof(ngx_http_enhanced_memcached_extract_headers) - 1)
static u_char ngx_http_enhanced_memcached_extract_headers[] = "EXTRACT_HEADERS" CRLF;

#define NGX_HTTP_ENHANCED_MEMCACHED_HEADER_STATUS  (sizeof(ngx_http_enhanced_memcached_header_status) - 1)
static u_char ngx_http_enhanced_memcached_header_status[] = "X-Nginx-Status";

static ngx_int_t
ngx_http_enhanced_memcached_handler(ngx_http_request_t *r)
{
    ngx_int_t                       rc;
    ngx_http_upstream_t            *u;
    ngx_http_enhanced_memcached_ctx_t       *ctx;
    ngx_http_enhanced_memcached_loc_conf_t  *mlcf;
    ngx_flag_t                      read_body;
    ngx_flag_t                      standard_filters;
    ngx_flag_t                      set_default_content_type;

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u = r->upstream;

    ngx_str_set(&u->schema, "memcached://");
    u->output.tag = (ngx_buf_tag_t) &ngx_http_enhanced_memcached_module;

    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_enhanced_memcached_module);

    if (!(r->method & mlcf->method_filter)) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    u->conf = &mlcf->upstream;

    u->reinit_request = ngx_http_enhanced_memcached_reinit_request;
    u->abort_request = ngx_http_enhanced_memcached_abort_request;
    u->finalize_request = ngx_http_enhanced_memcached_finalize_request;

    ctx = ngx_palloc(r->pool, sizeof(ngx_http_enhanced_memcached_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->request = r;

    ngx_http_set_ctx(r, ctx, ngx_http_enhanced_memcached_module);

    standard_filters = 1;
    read_body = 0;
    set_default_content_type = 1;

    if (mlcf->flush) {
      ctx->rest = ctx->end_len = NGX_HTTP_ENHANCED_MEMCACHED_CRLF;
      ctx->end = ngx_http_enhanced_memcached_crlf;
      u->create_request = ngx_http_enhanced_memcached_send_request_flush;
      u->process_header = ngx_http_enhanced_memcached_process_request_flush;
    }
    else if (mlcf->stats) {
      standard_filters = 0;
      u->input_filter_init = ngx_http_enhanced_memcached_filter_chunked_init;
      u->input_filter = ngx_http_enhanced_memcached_filter_chunked;
      ctx->rest = ctx->end_len = NGX_HTTP_ENHANCED_MEMCACHED_END;
      ctx->end = ngx_http_enhanced_memcached_end;
      u->create_request = ngx_http_enhanced_memcached_send_request_stats;
      u->process_header = ngx_http_enhanced_memcached_process_request_stats;
    }
    else if (mlcf->flush_namespace) {
      ctx->rest = ctx->end_len = NGX_HTTP_ENHANCED_MEMCACHED_CRLF;
      ctx->end = ngx_http_enhanced_memcached_crlf;
      ctx->key_status = UNKNOWN;
      ctx->when_key_ready = ngx_http_enhanced_memcached_send_request_incr_ns;
      u->create_request = ngx_http_enhanced_memcached_compute_key;
      u->process_header = ngx_http_enhanced_memcached_process_request_incr_ns;
    }
    else if(r->method & (NGX_HTTP_PUT)) {
      read_body = 1;
      ctx->rest = ctx->end_len = NGX_HTTP_ENHANCED_MEMCACHED_CRLF;
      ctx->end = ngx_http_enhanced_memcached_crlf;
      ctx->key_status = UNKNOWN;
      ctx->when_key_ready = ngx_http_enhanced_memcached_send_request_set;
      u->create_request = ngx_http_enhanced_memcached_compute_key;
      u->process_header = ngx_http_enhanced_memcached_process_request_set;
    }
    else if(r->method & (NGX_HTTP_DELETE)) {
      read_body = 1;
      ctx->rest = ctx->end_len = NGX_HTTP_ENHANCED_MEMCACHED_CRLF;
      ctx->end = ngx_http_enhanced_memcached_crlf;
      ctx->key_status = UNKNOWN;
      ctx->when_key_ready = ngx_http_enhanced_memcached_send_request_delete;
      u->create_request = ngx_http_enhanced_memcached_compute_key;
      u->process_header = ngx_http_enhanced_memcached_process_request_delete;
    }
    else {
      set_default_content_type = 0;
      ctx->rest = ctx->end_len = NGX_HTTP_ENHANCED_MEMCACHED_END;
      ctx->end = ngx_http_enhanced_memcached_end;
      ctx->key_status = UNKNOWN;
      ctx->when_key_ready = ngx_http_enhanced_memcached_send_request_get;
      u->create_request = ngx_http_enhanced_memcached_compute_key;
      u->process_header = ngx_http_enhanced_memcached_process_request_get;
    }

    u->input_filter_ctx = ctx;
    if (standard_filters) {
      u->input_filter_init = ngx_http_enhanced_memcached_filter_init;
      u->input_filter = ngx_http_enhanced_memcached_filter;
    }

    if (set_default_content_type) {
      if (ngx_http_set_content_type(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
      }
    }

    if (read_body) {
      rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init);
      if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
      }
    }
    else {
      r->main->count++;
      rc = ngx_http_discard_request_body(r);
      if (rc != NGX_OK) {
        return rc;
      }
      ngx_http_upstream_init(r);
    }

    return NGX_DONE;
}

static ngx_chain_t *
ngx_http_enhanced_memcached_create_buffer(ngx_http_request_t * r, size_t len)
{
    ngx_buf_t                      *b;
    ngx_chain_t                    *cl;

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NULL;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NULL;
    }

    cl->buf = b;
    cl->next = NULL;

    return cl;
}

static ngx_http_variable_value_t *
ngx_http_enhanced_memcached_md5(ngx_http_request_t * r, ngx_http_variable_value_t * v) {
    ngx_md5_t md5_ctx;
    u_char result[16];
    u_char * dumped_result;
    ngx_http_variable_value_t      *vv;

    dumped_result = (u_char *) ngx_palloc(r->pool, sizeof(result) * 2);
    if (dumped_result == NULL) {
      return NULL;
    }
    vv = (ngx_http_variable_value_t *) ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t));
    if (vv == NULL) {
      return NULL;
    }
    vv->len = sizeof(result) * 2;
    vv->data = dumped_result;

    ngx_md5_init(&md5_ctx);
    ngx_md5_update(&md5_ctx, v->data, v->len);
    ngx_md5_final(result, &md5_ctx);

    ngx_hex_dump(dumped_result, result, sizeof(result));

    return vv;
}

static void
ngx_http_enhanced_memcached_upstream_send_another_request_dummy_handler(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http upstream send another request dummy handler");
}

static ngx_int_t
ngx_http_enhanced_memcached_upstream_send_another_request(ngx_http_request_t *r, ngx_http_upstream_t *u);

static void
ngx_http_enhanced_memcached_upstream_send_another_request_handler(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http upstream send another request handler");

    ngx_http_enhanced_memcached_upstream_send_another_request(r, u);
}

static ngx_int_t
ngx_http_enhanced_memcached_upstream_send_another_request(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_int_t          rc;
    ngx_connection_t  *c;

    c = u->peer.connection;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream send another request");
    //
    // if (!u->request_sent && ngx_http_upstream_test_connect(c) != NGX_OK) {
    //     ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
    //     return;
    // }

    c->log->action = "sending request to upstream";

    rc = ngx_output_chain(&u->output, u->request_sent ? NULL : u->request_bufs);

    u->request_sent = 1;

    if (rc == NGX_ERROR) {
        return rc;
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    if (rc == NGX_AGAIN) {
       ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "enhanced memcached: ngx_output_chain return NGX_AGAIN");

        u->write_event_handler = ngx_http_enhanced_memcached_upstream_send_another_request_handler;

        ngx_add_timer(c->write, u->conf->send_timeout);

        if (ngx_handle_write_event(c->write, u->conf->send_lowat) != NGX_OK) {
          return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    /* rc == NGX_OK */

    if (c->tcp_nopush == NGX_TCP_NOPUSH_SET) {
        if (ngx_tcp_push(c->fd) == NGX_ERROR) {
            ngx_log_error(NGX_LOG_CRIT, c->log, ngx_socket_errno,
                          ngx_tcp_push_n " failed");
            return NGX_ERROR;
        }

        c->tcp_nopush = NGX_TCP_NOPUSH_UNSET;
    }

    ngx_add_timer(c->read, u->conf->read_timeout);

// #if 1
//     if (c->read->ready) {
//
//         /* post aio operation */
//
//         /*
//          * TODO comment
//          * although we can post aio operation just in the end
//          * of ngx_http_upstream_connect() CHECK IT !!!
//          * it's better to do here because we postpone header buffer allocation
//          */
//
//          return u->process_header(r);
//     }
// #endif

    u->write_event_handler = ngx_http_enhanced_memcached_upstream_send_another_request_dummy_handler;

    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_AGAIN;
}

static ngx_int_t
ngx_http_enhanced_memcached_initialize_namespace(ngx_http_request_t * r) {
  ngx_buf_t                      *b;
  ngx_chain_t                    *cl;
  ngx_http_enhanced_memcached_ctx_t       *ctx;

  ctx = ngx_http_get_module_ctx(r, ngx_http_enhanced_memcached_module);

  cl = ngx_http_enhanced_memcached_create_buffer(r, 4 + ctx->namespace_key.len + 11);
  if (cl == NULL) {
    return NGX_ERROR;
  }
  r->upstream->request_bufs = cl;
  r->upstream->request_sent = 0;

  b = cl->buf;

  *b->last++ = 's'; *b->last++ = 'e'; *b->last++ = 't'; *b->last++ = ' ';

  b->last = ngx_copy(b->last, ctx->namespace_key.data, ctx->namespace_key.len);

  *b->last++ = ' '; *b->last++ = '0'; *b->last++ = ' '; *b->last++ = '0'; *b->last++ = ' '; *b->last++ = '1';

  *b->last++ = CR; *b->last++ = LF;

  *b->last++ = '0';

  *b->last++ = CR; *b->last++ = LF;

  ctx->key_status = WAIT_INIT_NS;

  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                 "enhanced memcached: initialize namespace for: \"%V\"", &ctx->namespace_key);

  return ngx_http_enhanced_memcached_upstream_send_another_request(r, r->upstream);
}

static ngx_int_t
ngx_http_enhanced_memcached_set_key_with_namespace(ngx_http_request_t * r) {
  ngx_http_enhanced_memcached_ctx_t       *ctx;
  ngx_buf_t                      *b;

  ctx = ngx_http_get_module_ctx(r, ngx_http_enhanced_memcached_module);

  ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                 "enhanced memcached: compute key from \"%V\" for namespace \"%V\": \"%v\"",
                  &ctx->key, &ctx->namespace_key, &ctx->namespace_value);

  b = ngx_create_temp_buf(r->pool, ctx->namespace_key.len + ctx->key.len + ctx->namespace_value.len);
  b->last = ngx_copy(b->last, ctx->namespace_key.data, ctx->namespace_key.len);
  b->last = ngx_copy(b->last, ctx->key.data, ctx->key.len);
  b->last = ngx_copy(b->last, ctx->namespace_value.data, ctx->namespace_value.len);

  ctx->key.data = b->pos;
  ctx->key.len = ctx->namespace_key.len + ctx->key.len + ctx->namespace_value.len;

  ctx->key_status = READY;

  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                 "enhanced memcached: key with namespace: \"%V\"", &ctx->key);

  return NGX_OK;
}

static ngx_int_t
ngx_http_enhanced_memcached_process_key(ngx_http_request_t * r) {
  ngx_int_t                       rc;
  u_char                         *p, *len;
  ngx_str_t                       line;
  ngx_http_upstream_t             *u;
  ngx_http_enhanced_memcached_ctx_t       *ctx;
  off_t                           value_len;

  u = r->upstream;

  for (p = u->buffer.pos; p < u->buffer.last; p++) {
    if (*p == LF) {
      goto found;
    }
  }

  return NGX_AGAIN;

found:

  *p = '\0';

  line.len = p - u->buffer.pos - 1;
  line.data = u->buffer.pos;

  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                 "enhanced memcached: response when fetching namespace: \"%V\"", &line);

  ctx = ngx_http_get_module_ctx(r, ngx_http_enhanced_memcached_module);

  if (ctx->key_status == WAIT_GET_NS) {
    if (line.len >= sizeof("END") - 1 && ngx_strncmp(line.data, "END", sizeof("END") - 1) == 0) {
      ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                     "enhanced memcached: no namespace found for: \"%V\"", &ctx->namespace_key);

      u->buffer.pos = p + 1;

      return ngx_http_enhanced_memcached_initialize_namespace(r);
    }

    if (line.len >= sizeof("VALUE") - 1 && ngx_strncmp(line.data, "VALUE ", sizeof("VALUE ") - 1) == 0) {
      p = u->buffer.pos;

      p += sizeof("VALUE ") - 1;

      if (p + ctx->namespace_key.len <= u->buffer.last && ngx_strncmp(p, ctx->namespace_key.data, ctx->namespace_key.len) != 0) {
          ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "enhanced memcached: sent invalid key in response \"%V\" "
                        "for key \"%V\"  while getting namespace",
                        &line, &ctx->namespace_key);

        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
      }

      p += ctx->namespace_key.len;
      if (*p++ != ' ') {
         goto no_valid;
      }

      /* skip flags */

      while (*p) {
        if (*p++ == ' ') {
          goto length;
        }
      }

      goto no_valid;

length:

      len = p;

      while (*p && *p++ != CR) { /* void */ }

      value_len = ngx_atoof(len, p - len - 1);

      u->buffer.pos += line.len + 2;

      if (u->buffer.pos + value_len + NGX_HTTP_ENHANCED_MEMCACHED_END > u->buffer.last) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "enhanced memcached: sent invalid response "
                       "for key \"%V\"  while getting namespace",
                        &ctx->namespace_key);
        return NGX_ERROR;
      }

      ctx->namespace_value.data = u->buffer.pos;
      ctx->namespace_value.len = value_len;

      rc = ngx_http_enhanced_memcached_set_key_with_namespace(r);
      if (rc != NGX_OK) {
        return rc;
      };

      u->buffer.pos += value_len;

      if (u->buffer.pos + NGX_HTTP_ENHANCED_MEMCACHED_END <= u->buffer.last && ngx_strncmp(u->buffer.pos, ngx_http_enhanced_memcached_end, NGX_HTTP_ENHANCED_MEMCACHED_END) != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "enhanced memcached: sent invalid response "
                       "for key \"%V\"  while getting namespace",
                        &ctx->namespace_key);
        return NGX_ERROR;
      }
      u->buffer.pos += NGX_HTTP_ENHANCED_MEMCACHED_END;

      rc = ctx->when_key_ready(r);
      if (rc != NGX_OK) {
        return rc;
      };

      r->upstream->request_sent = 0;

      return ngx_http_enhanced_memcached_upstream_send_another_request(r, r->upstream);
    }
  }

  if (ctx->key_status == WAIT_INIT_NS) {
    if (line.len >= sizeof("STORED") - 1 && ngx_strncmp(line.data, "STORED", sizeof("STORED") - 1) == 0) {
      ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                     "enhanced memcached: namespace initialized for: \"%V\"", &ctx->namespace_key);

      u->buffer.pos = p + 1;

      ctx->namespace_value.data = (u_char *) "0";
      ctx->namespace_value.len = sizeof("0") - 1;

      rc = ngx_http_enhanced_memcached_set_key_with_namespace(r);
      if (rc != NGX_OK) {
        return rc;
      };

      rc = ctx->when_key_ready(r);
      if (rc != NGX_OK) {
        return rc;
      };

      r->upstream->request_sent = 0;

      return ngx_http_enhanced_memcached_upstream_send_another_request(r, r->upstream);
    }
  }

  return NGX_ERROR;

no_valid:

  ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "enhanced memcached: sent invalid response while getting namespace: \"%V\"", &line);

  return NGX_HTTP_UPSTREAM_INVALID_HEADER;
}

static ngx_int_t
ngx_http_enhanced_memcached_get_namespace(ngx_http_request_t * r, ngx_http_variable_value_t *namespace) {
  ngx_http_enhanced_memcached_ctx_t       *ctx;
  ngx_buf_t                      *b;
  ngx_chain_t                    *cl;

  ctx = ngx_http_get_module_ctx(r, ngx_http_enhanced_memcached_module);

  ctx->key_status = WAIT_GET_NS;

  cl = ngx_http_enhanced_memcached_create_buffer(r, 4 + 6 + namespace->len + 2);
  if (cl == NULL) {
    return NGX_ERROR;
  }

  r->upstream->request_bufs = cl;

  b = cl->buf;

  *b->last++ = 'g'; *b->last++ = 'e'; *b->last++ = 't'; *b->last++ = ' ';

  ctx->namespace_key.data = b->last;

  *b->last++ = '_'; *b->last++ = '_'; *b->last++ = 'n'; *b->last++ = 's'; *b->last++ = '_'; *b->last++ = '_';

  b->last = ngx_copy(b->last, namespace->data, namespace->len);

  ctx->namespace_key.len = b->last - ctx->namespace_key.data;

  *b->last++ = CR; *b->last++ = LF;

  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                 "enhanced memcached: fetching namespace for: \"%V\"", &ctx->namespace_key);

  return NGX_OK;
}

static ngx_int_t
ngx_http_enhanced_memcached_compute_key(ngx_http_request_t * r) {
  size_t                          len;
  uintptr_t                       escape;
  ngx_http_enhanced_memcached_ctx_t       *ctx;
  ngx_http_enhanced_memcached_loc_conf_t  *mlcf;
  ngx_http_variable_value_t      *vv;
  ngx_buf_t                      *b;

  mlcf = ngx_http_get_module_loc_conf(r, ngx_http_enhanced_memcached_module);

  vv = ngx_http_get_indexed_variable(r, mlcf->key_index);

  if (vv == NULL || vv->not_found || vv->len == 0) {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "enhanced memcached: the \"$memcached_key\" variable is not set");
      return NGX_ERROR;
  }

  if (mlcf->hash_keys_with_md5) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "enhanced memcached: key before hash: \"%v\"", vv);

    vv = ngx_http_enhanced_memcached_md5(r, vv);
    if (vv == NULL) {
      return NGX_ERROR;
    }
  }

  escape = 2 * ngx_escape_uri(NULL, vv->data, vv->len, NGX_ESCAPE_MEMCACHED);

  len = vv->len + escape;

  b = ngx_create_temp_buf(r->pool, len);
  if (b == NULL) {
    return NGX_ERROR;
  }

  ctx = ngx_http_get_module_ctx(r, ngx_http_enhanced_memcached_module);

  ctx->key.data = b->last;

  if (escape == 0) {
      b->last = ngx_copy(b->last, vv->data, vv->len);
  } else {
      b->last = (u_char *) ngx_escape_uri(b->last, vv->data, vv->len, NGX_ESCAPE_MEMCACHED);
  }

  ctx->key.len = b->last - ctx->key.data;

  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                 "enhanced memcached: key: \"%V\"", &ctx->key);

  vv = ngx_http_get_indexed_variable(r, mlcf->key_namespace_index);

  if (vv == NULL || vv->not_found || vv->len == 0) {
    ctx->key_status = READY;
    return ctx->when_key_ready(r);
  }
  return ngx_http_enhanced_memcached_get_namespace(r, vv);
}

static ngx_int_t
ngx_http_enhanced_memcached_send_request_incr_ns(ngx_http_request_t *r) {
  ngx_chain_t                    *cl;
  ngx_buf_t                      *b;
  ngx_http_enhanced_memcached_ctx_t       *ctx;

  ctx = ngx_http_get_module_ctx(r, ngx_http_enhanced_memcached_module);

  cl = ngx_http_enhanced_memcached_create_buffer(r, 5 + ctx->namespace_key.len + 2 + 2);
  if (cl == NULL) {
    return NGX_ERROR;
  }

  r->upstream->request_bufs = cl;

  b = cl->buf;

  *b->last++ = 'i'; *b->last++ = 'n'; *b->last++ = 'c'; *b->last++ = 'r'; *b->last++ = ' ';

  b->last = ngx_copy(b->last, ctx->namespace_key.data, ctx->namespace_key.len);

  *b->last++ = ' '; *b->last++ = '1';

  *b->last++ = CR; *b->last++ = LF;

  return NGX_OK;
}


static ngx_int_t
ngx_http_enhanced_memcached_send_request_get(ngx_http_request_t *r)
{
  ngx_buf_t                      *b;
  ngx_chain_t                    *cl;
  ngx_http_enhanced_memcached_ctx_t       *ctx;

  ctx = ngx_http_get_module_ctx(r, ngx_http_enhanced_memcached_module);

  cl = ngx_http_enhanced_memcached_create_buffer(r, 4 + ctx->key.len + 2);
  if (cl == NULL) {
    return NGX_ERROR;
  }

  r->upstream->request_bufs = cl;

  b = cl->buf;

  *b->last++ = 'g'; *b->last++ = 'e'; *b->last++ = 't'; *b->last++ = ' ';

  b->last = ngx_copy(b->last, ctx->key.data, ctx->key.len);

  *b->last++ = CR; *b->last++ = LF;

  return NGX_OK;
}

static ngx_int_t
ngx_http_enhanced_memcached_send_request_set(ngx_http_request_t *r)
{
    uintptr_t                       bytes_len;
    off_t                           bytes;
    ngx_http_variable_value_t       default_expire_value;
    ngx_buf_t                      *b;
    ngx_chain_t                    *cl, *in;
    ngx_http_variable_value_t      *vv;
    ngx_http_enhanced_memcached_loc_conf_t  *mlcf;
    u_char                          bytes_buf[NGX_UINT32_LEN];
    ngx_http_enhanced_memcached_ctx_t       *ctx;

    default_expire_value.data = (u_char *) "0";
    default_expire_value.len = 1;

    ctx = ngx_http_get_module_ctx(r, ngx_http_enhanced_memcached_module);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                     "enhanced memcached: set value for key: \"%V\"", &ctx->key);

    cl = ngx_http_enhanced_memcached_create_buffer(r, 4 + ctx->key.len + 3);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    r->upstream->request_bufs = cl;

    b = cl->buf;

    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_enhanced_memcached_module);
    vv = ngx_http_get_indexed_variable(r, mlcf->use_add_index);

    if (vv == NULL || vv->not_found || vv->len == 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "enhanced memcached: use set command");
        *b->last++ = 's'; *b->last++ = 'e'; *b->last++ = 't'; *b->last++ = ' ';
    }
    else {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "enhanced memcached: use add command");
        *b->last++ = 'a'; *b->last++ = 'd'; *b->last++ = 'd'; *b->last++ = ' ';
    }

    b->last = ngx_copy(b->last, ctx->key.data, ctx->key.len);

    *b->last++ = ' '; *b->last++ = '0'; *b->last++ = ' ';

    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_enhanced_memcached_module);
    vv = ngx_http_get_indexed_variable(r, mlcf->expire_index);

    if (vv == NULL || vv->not_found || vv->len == 0) {
        vv = &default_expire_value;
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "enhanced memcached: the \"$memcached_expire\" variable is not set, use 0 value");
    }
    else {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "enhanced memcached: expire is set to \"%v\"", vv);
    }

    bytes = 0;
    for (in = r->request_body->bufs; in; in = in->next) {
        bytes += ngx_buf_size(in->buf);
    }

    if (bytes != r->headers_in.content_length_n) {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "enhanced memcached: put : wrong content length size, headers %d, found %d", r->headers_in.content_length_n, bytes);
      return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "enhanced memcached: put : size %d", bytes);

    bytes_len = ngx_snprintf(bytes_buf, sizeof(bytes_buf), "%O", bytes) - bytes_buf;

    cl->next = ngx_http_enhanced_memcached_create_buffer(r, vv->len + 1 + bytes_len  + 2);
    cl = cl->next;
    if (cl == NULL) {
      return NGX_ERROR;
    }
    b = cl->buf;

    b->last = ngx_copy(b->last, vv->data, vv->len);

    *b->last++ = ' ';

    b->last = ngx_copy(b->last, bytes_buf, bytes_len);

    *b->last++ = CR; *b->last++ = LF;

    in = r->request_body->bufs;

    while (in) {
      cl->next = ngx_alloc_chain_link(r->pool);
      cl = cl->next;
      if (cl == NULL) {
        return NGX_ERROR;
      }

      cl->buf = ngx_calloc_buf(r->pool);
      if (cl->buf == NULL) {
        return NGX_ERROR;
      }

      cl->buf->memory = 1;
      *cl->buf = *in->buf;

      in = in->next;
    }

    cl->next = ngx_http_enhanced_memcached_create_buffer(r, 2);
    cl = cl->next;
    if (cl == NULL) {
        return NGX_ERROR;
    }
    b = cl->buf;

    *b->last++ = CR; *b->last++ = LF;

    return NGX_OK;
}

static ngx_int_t
ngx_http_enhanced_memcached_send_request_delete(ngx_http_request_t *r)
{
    ngx_buf_t                      *b;
    ngx_chain_t                    *cl;
    ngx_http_enhanced_memcached_ctx_t       *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_enhanced_memcached_module);

    cl = ngx_http_enhanced_memcached_create_buffer(r, 7 + ctx->key.len + 2);
    if (cl == NULL) {
        return NGX_ERROR;
    }
    b = cl->buf;

    *b->last++ = 'd'; *b->last++ = 'e'; *b->last++ = 'l'; *b->last++ = 'e'; *b->last++ = 't'; *b->last++ = 'e'; *b->last++ = ' ';

    r->upstream->request_bufs = cl;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "enhanced memcached: send delete command");

    b->last = ngx_copy(b->last, ctx->key.data, ctx->key.len);

    *b->last++ = CR; *b->last++ = LF;

    return NGX_OK;
}

static ngx_int_t
ngx_http_enhanced_memcached_create_request_fixed_str(ngx_http_request_t *r, char * cmd, char * str, u_int str_len)
{
    ngx_buf_t                      *b;
    ngx_chain_t                    *cl;
    ngx_http_enhanced_memcached_ctx_t       *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_enhanced_memcached_module);

    ctx->key.data = (u_char *) str;
    ctx->key.len = str_len;

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "enhanced memcached: %s requested", cmd);

    cl = ngx_http_enhanced_memcached_create_buffer(r, str_len + 2);
    if (cl == NULL) {
      return NGX_ERROR;
    }
    b = cl->buf;

    r->upstream->request_bufs = cl;

    b->last = ngx_copy(b->last, str, str_len);

    *b->last++ = CR; *b->last++ = LF;

    return NGX_OK;
}

static ngx_int_t
ngx_http_enhanced_memcached_send_request_flush(ngx_http_request_t *r)
{
    return ngx_http_enhanced_memcached_create_request_fixed_str(r, "flush", "flush_all", sizeof("flush_all") - 1);
}

static ngx_int_t
ngx_http_enhanced_memcached_send_request_stats(ngx_http_request_t *r)
{
    return ngx_http_enhanced_memcached_create_request_fixed_str(r, "stats", "stats", sizeof("stats") - 1);
}

static ngx_int_t
ngx_http_enhanced_memcached_reinit_request(ngx_http_request_t *r)
{
    return NGX_OK;
}

static ngx_int_t
ngx_http_enhanced_memcached_process_request_get(ngx_http_request_t *r)
{
    u_char                    *p, *len;
    ngx_str_t                  line;
    ngx_http_upstream_t       *u;
    ngx_http_enhanced_memcached_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_enhanced_memcached_module);

    if (ctx->key_status != READY) {
      return ngx_http_enhanced_memcached_process_key(r);
    }

    u = r->upstream;

    for (p = u->buffer.pos; p < u->buffer.last; p++) {
        if (*p == LF) {
            goto found;
        }
    }

    return NGX_AGAIN;

found:

    *p = '\0';

    line.len = p - u->buffer.pos - 1;
    line.data = u->buffer.pos;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "enhanced memcached: response: \"%V\"", &line);

    p = u->buffer.pos;

    if (line.len >= sizeof("VALUE") - 1 && ngx_strncmp(line.data, "VALUE ", sizeof("VALUE ") - 1) == 0) {

        p += sizeof("VALUE ") - 1;

        if (p + ctx->key.len <= u->buffer.last && ngx_strncmp(p, ctx->key.data, ctx->key.len) != 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "enhanced memcached: sent invalid key in response \"%V\" "
                          "for key \"%V\"",
                          &line, &ctx->key);

            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }

        p += ctx->key.len;

        if (*p++ != ' ') {
            goto no_valid;
        }

        /* skip flags */

        while (*p) {
            if (*p++ == ' ') {
                goto length;
            }
        }

        goto no_valid;

length:

        len = p;

        while (*p && *p++ != CR) { /* void */ }

        u->headers_in.content_length_n = ngx_atoof(len, p - len - 1);
        if (u->headers_in.content_length_n == -1) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "enhanced memcached: sent invalid length in response \"%V\" "
                          "for key \"%V\"",
                          &line, &ctx->key);
            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }

        u->buffer.pos += line.len + 2;

        if (u->buffer.pos + NGX_HTTP_ENHANCED_MEMCACHED_EXTRACT_HEADERS <= u->buffer.last
          && ngx_strncmp(u->buffer.pos, ngx_http_enhanced_memcached_extract_headers, NGX_HTTP_ENHANCED_MEMCACHED_EXTRACT_HEADERS) == 0) {

          ngx_table_elt_t                *h;
          ngx_int_t                       rc;
          ngx_int_t                       status;
          ngx_http_upstream_main_conf_t  *umcf;
          ngx_http_upstream_header_t     *hh;
          ngx_table_elt_t                *etag;
          ngx_table_elt_t                *last_modified;
          ngx_table_elt_t                *content_length;

          content_length = NULL;
          last_modified = NULL;
          etag = NULL;
          status = 200;

          ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                         "enhanced memcached: extracting headers from memcached value");

          u->buffer.pos += NGX_HTTP_ENHANCED_MEMCACHED_EXTRACT_HEADERS;
          u->headers_in.content_length_n -= NGX_HTTP_ENHANCED_MEMCACHED_EXTRACT_HEADERS;

          if (u->headers_in.content_length_n == 0) {
            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
          }

          umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

          while (1) {
            p = u->buffer.pos;

            rc = ngx_http_parse_header_line(r, &r->upstream->buffer, 1);

            if (rc == NGX_OK) {

              /* a header line has been parsed successfully */

              if ((r->header_name_end - r->header_name_start) == NGX_HTTP_ENHANCED_MEMCACHED_HEADER_STATUS && ngx_strncmp(r->header_name_start, ngx_http_enhanced_memcached_header_status, NGX_HTTP_ENHANCED_MEMCACHED_HEADER_STATUS) == 0) {
                status = ngx_atoof(r->header_start, r->header_end - r->header_start);
                if (status < 100) {
                  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                         "wrong value for status: \"%d\"", status);
                  return NGX_ERROR;
                }
                u->headers_in.content_length_n -= u->buffer.pos - p;
                continue;
              }

              h = ngx_list_push(&r->upstream->headers_in.headers);
              if (h == NULL) {
                return NGX_ERROR;
              }

              h->hash = r->header_hash;

              h->key.len = r->header_name_end - r->header_name_start;
              h->value.len = r->header_end - r->header_start;

              h->key.data = ngx_pnalloc(r->pool,
                               h->key.len + 1 + h->value.len + 1 + h->key.len);
              if (h->key.data == NULL) {
                  return NGX_ERROR;
              }

              h->value.data = h->key.data + h->key.len + 1;
              h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1;

              ngx_cpystrn(h->key.data, r->header_name_start, h->key.len + 1);
              ngx_cpystrn(h->value.data, r->header_start, h->value.len + 1);

              if (h->key.len == r->lowcase_index) {
                ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);
              } else {
                ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
              }

              hh = ngx_hash_find(&umcf->headers_in_hash, h->hash,
                                 h->lowcase_key, h->key.len);

              if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
                return NGX_ERROR;
              }

              if (h->key.len == sizeof("ETag") - 1 && ngx_strncmp(h->key.data, "ETag", h->key.len) == 0) {
                etag = h;
              }

              if (h->key.len == sizeof("Last-Modified") - 1 && ngx_strncmp(h->key.data, "Last-Modified", h->key.len) == 0) {
                last_modified = h;
              }

              if (h->key.len == sizeof("Content-Length") - 1 && ngx_strncmp(h->key.data, "Content-Length", h->key.len) == 0) {
                content_length = h;
              }

              ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "enhanced memcached: extracted header: \"%V: %V\"",
                           &h->key, &h->value);

              u->headers_in.content_length_n -= u->buffer.pos - p;

              continue;
            }

            if (rc == NGX_HTTP_PARSE_HEADER_DONE) {

              /* a whole header has been parsed successfully */

              ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "enhanced memcached: header done");

              if (etag != NULL && r->headers_in.if_none_match != NULL) {
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                            "enhanced memcached have etag and if-none-match");
                if (r->headers_in.if_none_match->value.len == etag->value.len) {
                  if (!ngx_strncmp(r->headers_in.if_none_match->value.data, etag->value.data, etag->value.len)) {
                    u->headers_in.status_n = 304;
                    u->state->status = 304;

                    u->headers_in.content_length_n = -1;
                    if (u->headers_in.content_length) {
                      u->headers_in.content_length->hash = 0;
                      u->headers_in.content_length = NULL;
                    }

                    if (u->headers_in.content_type) {
                      u->headers_in.content_type->hash = 0;
                      u->headers_in.content_type = NULL;
                    }

                    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                "enhanced memcached sent not modified (etag)");
                    return NGX_OK;
                  }
                }
              }

              if (last_modified != NULL && r->headers_in.if_modified_since != NULL) {
                time_t                     ims_in;
                time_t                     ims_memcached;
                ngx_http_core_loc_conf_t  *clcf;

                clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

                if (clcf->if_modified_since != NGX_HTTP_IMS_OFF) {
                  ims_in = ngx_http_parse_time(r->headers_in.if_modified_since->value.data,
                                            r->headers_in.if_modified_since->value.len);

                  ims_memcached = ngx_http_parse_time(last_modified->value.data, last_modified->value.len);

                  if (ims_in == ims_memcached || (clcf->if_modified_since != NGX_HTTP_IMS_EXACT && ims_in >= ims_memcached)) {
                    u->headers_in.status_n = 304;
                    u->state->status = 304;

                    u->headers_in.content_length_n = -1;
                    if (u->headers_in.content_length) {
                      u->headers_in.content_length->hash = 0;
                      u->headers_in.content_length = NULL;
                    }

                    if (u->headers_in.content_type) {
                      u->headers_in.content_type->hash = 0;
                      u->headers_in.content_type = NULL;
                    }

                    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                "enhanced memcached sent not modified");
                    return NGX_OK;
                  }
                }
              }

              if (status < 300) {
                if (ngx_http_set_content_type(r) != NGX_OK) {
                  return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
              }

              u->headers_in.content_length_n -= 2;
              if (content_length != NULL) {
                u->headers_in.content_length_n = ngx_atoi(content_length->value.data, content_length->value.len);
              }

              u->headers_in.status_n = status;
              u->state->status = status;

              return NGX_OK;
            }

            if (rc == NGX_AGAIN) {
              ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "enhanced memcached: manage http headers on multiple process_header call is not implemented");
              return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            }

            /* there was error while a header line parsing */

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "enhanced memcached: value contain invalid header");

            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
          }
        }

        if (ngx_http_set_content_type(r) != NGX_OK) {
          return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        u->headers_in.status_n = 200;
        u->state->status = 200;
        u->keepalive = 1;

        return NGX_OK;
    }

    if (u->buffer.pos + sizeof("END") - 1 <= u->buffer.last && ngx_strncmp(u->buffer.pos, "END", sizeof("END") - 1) == 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "enhanced memcached: key not found: \"%V\"", &ctx->key);

        u->headers_in.status_n = 404;
        u->state->status = 404;
        u->keepalive = 1;

        return NGX_OK;
    }

no_valid:

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "enhanced memcached: sent invalid response: \"%V\"", &line);

    return NGX_HTTP_UPSTREAM_INVALID_HEADER;
}

static ngx_int_t
ngx_http_enhanced_memcached_process_request_return_string(ngx_http_request_t *r, char * cmd, u_char * str, u_int str_len, int other_code, char * str_other_code, u_int str_len_other_code)
{
    int                      return_code;
    u_char                    *p;
    ngx_str_t                  line;
    ngx_http_upstream_t       *u;
    ngx_http_enhanced_memcached_ctx_t  *ctx;

    u = r->upstream;

    for (p = u->buffer.pos; p < u->buffer.last; p++) {
        if (*p == LF) {
            goto found;
        }
    }

    return NGX_AGAIN;

found:

    ctx = ngx_http_get_module_ctx(r, ngx_http_enhanced_memcached_module);

    line.len = p - u->buffer.pos - 1;
    line.data = u->buffer.pos;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "enhanced memcached: response: \"%V\" for key \"%V\"", &line, &ctx->key);

    return_code = -1;

    if (str_len <= line.len && ngx_strncmp(line.data, str, str_len) == 0) {
      return_code = 200;
    }

    if (other_code != -1) {
      if (str_len <= line.len && ngx_strncmp(line.data, str_other_code, str_len_other_code) == 0) {
        return_code = other_code;
      }
    }

    if (return_code == -1) {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "enhanced memcached: %s invalid response for key \"%V\"",
                    cmd, &ctx->key);
      return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }

    r->headers_out.content_type.data = (u_char *) "text/plain";
    r->headers_out.content_type.len = sizeof("text/plain") - 1;
    r->headers_out.content_type_len = sizeof("text/plain") - 1;
    r->headers_out.content_type_lowcase = NULL;

    u->headers_in.status_n = return_code;
    u->state->status = return_code;
    u->headers_in.content_length_n = line.len;

    return NGX_OK;
}


static ngx_int_t
ngx_http_enhanced_memcached_process_request_set(ngx_http_request_t *r)
{
  ngx_http_enhanced_memcached_ctx_t  *ctx;

  ctx = ngx_http_get_module_ctx(r, ngx_http_enhanced_memcached_module);

  if (ctx->key_status != READY) {
    return ngx_http_enhanced_memcached_process_key(r);
  }

  return ngx_http_enhanced_memcached_process_request_return_string(r, "set", (u_char *) "STORED", sizeof("STORED") - 1, 409, "NOT_STORED", sizeof("NOT_STORED") - 1);
}

static ngx_int_t
ngx_http_enhanced_memcached_process_request_flush(ngx_http_request_t *r)
{
  ngx_int_t rc;
  rc = ngx_http_enhanced_memcached_process_request_return_string(r, "flush", (u_char *) "OK", sizeof("OK") - 1, -1, NULL, -1);
  if (rc == NGX_OK) {
     ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "enhanced memcached: flush OK");
  }
  return rc;
}

static ngx_int_t
ngx_http_enhanced_memcached_process_request_incr_ns(ngx_http_request_t *r)
{
  ngx_int_t                       rc;
  off_t                           current;
  u_char                          bytes_buf[NGX_UINT32_LEN];
  u_int                           bytes_len;

  ngx_http_enhanced_memcached_ctx_t  *ctx;

  ctx = ngx_http_get_module_ctx(r, ngx_http_enhanced_memcached_module);

  if (ctx->key_status != READY) {
    return ngx_http_enhanced_memcached_process_key(r);
  }

  current = ngx_atoof(ctx->namespace_value.data, ctx->namespace_value.len);

  ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "enhanced memcached: current namespace \"%V\", value : %d", &ctx->namespace_key, current);

  current ++;
  bytes_len = ngx_snprintf(bytes_buf, sizeof(bytes_buf), "%O", current) - bytes_buf;

  rc = ngx_http_enhanced_memcached_process_request_return_string(r, "incr ns", bytes_buf, bytes_len, -1, NULL, -1);
  if (rc == NGX_OK) {
     ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "enhanced memcached: incr ns OK");
  }
  return rc;
}

static ngx_int_t
ngx_http_enhanced_memcached_process_request_delete(ngx_http_request_t *r)
{
  ngx_http_enhanced_memcached_ctx_t  *ctx;

  ctx = ngx_http_get_module_ctx(r, ngx_http_enhanced_memcached_module);

  if (ctx->key_status != READY) {
   return ngx_http_enhanced_memcached_process_key(r);
  }

  ngx_int_t rc;
  rc = ngx_http_enhanced_memcached_process_request_return_string(r, "delete", (u_char *) "DELETED", sizeof("DELETED") - 1, 404, "NOT_FOUND", sizeof("NOT_FOUND") - 1);
  if (rc == NGX_OK) {
     ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "enhanced memcached: delete OK");
  }
  return rc;
}

static ngx_int_t
ngx_http_enhanced_memcached_process_request_stats(ngx_http_request_t *r)
{
    ngx_http_upstream_t       *u;

    u = r->upstream;

    if ((u->buffer.last - u->buffer.pos - NGX_HTTP_ENHANCED_MEMCACHED_STATS) > 0) {
      if (ngx_strncmp(u->buffer.pos, ngx_http_enhanced_memcached_stats, NGX_HTTP_ENHANCED_MEMCACHED_STATS) == 0) {
        u->headers_in.status_n = 200;
        u->state->status = 200;

        r->headers_out.content_type.data = (u_char *) "text/plain";
        r->headers_out.content_type.len = sizeof("text/plain") - 1;
        r->headers_out.content_type_len = sizeof("text/plain") - 1;
        r->headers_out.content_type_lowcase = NULL;

        r->upstream->headers_in.content_length_n = -1;
        r->upstream->headers_in.chunked = 1;

        return NGX_OK;
      }
    }
    return NGX_HTTP_UPSTREAM_INVALID_HEADER;
}

static ngx_int_t
ngx_http_enhanced_memcached_filter_init(void *data)
{
    ngx_http_enhanced_memcached_ctx_t  *ctx = data;

    ngx_http_upstream_t  *u;

    u = ctx->request->upstream;

#if nginx_version <= 1005003

    if (u->headers_in.status_n != 404) {
        u->length += ctx->end_len;
    }

#else

    if (u->headers_in.status_n != 404) {
        u->length = u->headers_in.content_length_n + ctx->end_len;
        ctx->rest = ctx->end_len;
    }
    else {
        u-> length = 0;
    }

#endif

    return NGX_OK;
}

static ngx_int_t
ngx_http_enhanced_memcached_filter(void *data, ssize_t bytes)
{
    ngx_http_enhanced_memcached_ctx_t  *ctx = data;

    u_char               *last;
    ngx_buf_t            *b;
    ngx_chain_t          *cl, **ll;
    ngx_http_upstream_t  *u;

    u = ctx->request->upstream;
    b = &u->buffer;

    if (u->length == (ssize_t) ctx->rest) {

        if (ngx_strncmp(b->last,
                   ctx->end + ctx->end_len - ctx->rest,
                   bytes)
            != 0)
        {
            ngx_log_error(NGX_LOG_ERR, ctx->request->connection->log, 0,
                          "enhanced memcached: sent invalid trailer");

            u->length = 0;
            ctx->rest = 0;

            return NGX_OK;
        }

        u->length -= bytes;
        ctx->rest -= bytes;

        if (u->length == 0) {
            u->keepalive = 1;
        }

        return NGX_OK;
    }

    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = ngx_chain_get_free_buf(ctx->request->pool, &u->free_bufs);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf->flush = 1;
    cl->buf->memory = 1;

    *ll = cl;

    last = b->last;
    cl->buf->pos = last;
    b->last += bytes;
    cl->buf->last = b->last;
    cl->buf->tag = u->output.tag;

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "enhanced memcached: filter bytes:%z size:%z length:%z rest:%z",
                   bytes, b->last - b->pos, u->length, ctx->rest);

    if (bytes <= (ssize_t) (u->length - ctx->end_len)) {
        u->length -= bytes;
        return NGX_OK;
    }

    last += (size_t) u->length - ctx->end_len;

    if (ngx_strncmp(last, ctx->end, b->last - last) != 0) {
        ngx_log_error(NGX_LOG_ERR, ctx->request->connection->log, 0,
                      "enhanced memcached: sent invalid trailer");

        b->last = last;
        cl->buf->last = last;
        u->length = 0;
        ctx->rest = 0;

        return NGX_OK;
    }

    ctx->rest -= b->last - last;
    b->last = last;
    cl->buf->last = last;
    u->length = ctx->rest;

    if (u->length == 0) {
        u->keepalive = 1;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_enhanced_memcached_filter_chunked_init(void *data)
{
  return NGX_OK;
}

static ngx_int_t
ngx_http_enhanced_memcached_filter_chunked(void *data, ssize_t bytes)
{
  ngx_http_enhanced_memcached_ctx_t  *ctx = data;
  ngx_http_request_t  *r = ctx->request;

  ngx_buf_t            *b;
  ngx_chain_t          *cl, **ll;
  ngx_http_upstream_t  *u;

  u = r->upstream;

  for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
      ll = &cl->next;
  }

  cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs);
  if (cl == NULL) {
      return NGX_ERROR;
  }

  *ll = cl;

  cl->buf->flush = 1;
  cl->buf->memory = 1;

  b = &u->buffer;

  if (((bytes - ctx->end_len) > 0) && ngx_strncmp(b->last + bytes - ctx->end_len, ctx->end, ctx->end_len) == 0) {
    bytes -= ctx->end_len;
    cl->buf->last_buf = 1;
  }


  cl->buf->pos = b->last;
  b->last += bytes;
  cl->buf->last = b->last;

  return NGX_OK;
}

static void
ngx_http_enhanced_memcached_abort_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort enhanced memcached request");
    return;
}


static void
ngx_http_enhanced_memcached_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize enhanced memcached request");
    return;
}


static void *
ngx_http_enhanced_memcached_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_enhanced_memcached_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_enhanced_memcached_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->upstream.bufs.num = 0;
     *     conf->upstream.next_upstream = 0;
     *     conf->upstream.temp_path = NULL;
     *     conf->upstream.uri = { 0, NULL };
     *     conf->upstream.location = NULL;
     */

    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;

    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;

    /* the hardcoded values */
    conf->upstream.cyclic_temp_file = 0;
    conf->upstream.buffering = 0;
    conf->upstream.ignore_client_abort = 0;
    conf->upstream.send_lowat = 0;
    conf->upstream.bufs.num = 0;
    conf->upstream.busy_buffers_size = 0;
    conf->upstream.max_temp_file_size = 0;
    conf->upstream.temp_file_write_size = 0;
    conf->upstream.intercept_errors = 1;
    conf->upstream.intercept_404 = 1;
    conf->upstream.pass_request_headers = 0;
    conf->upstream.pass_request_body = 0;

    conf->hash_keys_with_md5 = NGX_CONF_UNSET;
    conf->allow_put = NGX_CONF_UNSET;
    conf->allow_delete = NGX_CONF_UNSET;
    conf->stats = NGX_CONF_UNSET;
    conf->flush = NGX_CONF_UNSET;
    conf->flush_namespace = NGX_CONF_UNSET;

    conf->key_index = NGX_CONF_UNSET;
    conf->expire_index = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_enhanced_memcached_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_enhanced_memcached_loc_conf_t *prev = parent;
    ngx_http_enhanced_memcached_loc_conf_t *conf = child;

    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    ngx_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              (size_t) ngx_pagesize);

    conf->upstream.hide_headers_hash.buckets = ngx_pcalloc(cf->pool, sizeof(ngx_hash_elt_t *));
    conf->upstream.hide_headers_hash.size = 1;

    if (conf->upstream.upstream == NULL) {
        conf->upstream.upstream = prev->upstream.upstream;
    }

    if (conf->key_index == NGX_CONF_UNSET) {
        conf->key_index = prev->key_index;
    }

    if (conf->expire_index == NGX_CONF_UNSET) {
        conf->expire_index = prev->expire_index;
    }

    if (conf->hash_keys_with_md5 == NGX_CONF_UNSET) {
      conf->hash_keys_with_md5 = 0;
    }

    if (conf->allow_put == NGX_CONF_UNSET) {
      conf->allow_put = 0;
    }

    if (conf->allow_delete == NGX_CONF_UNSET) {
      conf->allow_delete = 0;
    }

    if (conf->stats == NGX_CONF_UNSET) {
      conf->stats = 0;
    }

    if (conf->flush == NGX_CONF_UNSET) {
      conf->flush = 0;
    }

    if (conf->flush_namespace == NGX_CONF_UNSET) {
      conf->flush_namespace = 0;
    }

    if ((conf->flush && conf->stats) || (conf->flush && conf->allow_put) || (conf->stats && conf->allow_put) || (conf->flush && conf->flush_namespace) || (conf->stats && conf->flush_namespace) || (conf->allow_put && conf->flush_namespace)) {
      ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "enhanced memcached: configuration: stats, flush, flush_namespace and allow put are mutually exclusive");
      return NGX_CONF_ERROR;
    }

    if (conf->flush || conf->stats || conf->flush_namespace) {
      conf->method_filter = NGX_HTTP_GET;
    }
    else {
      conf->method_filter = NGX_HTTP_GET|NGX_HTTP_HEAD;
      if (conf->allow_put) {
        conf->method_filter |= NGX_HTTP_PUT;
      }
      if (conf->allow_delete) {
        conf->method_filter |= NGX_HTTP_DELETE;
      }
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_enhanced_memcached_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_enhanced_memcached_loc_conf_t *mlcf = conf;

    ngx_str_t                 *value;
    ngx_url_t                  u;
    ngx_http_core_loc_conf_t  *clcf;

    if (mlcf->upstream.upstream) {
        return "is duplicate";
    }

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.no_resolve = 1;

    mlcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
    if (mlcf->upstream.upstream == NULL) {
        return NGX_CONF_ERROR;
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_http_enhanced_memcached_handler;

    if (clcf->name.data[clcf->name.len - 1] == '/') {
        clcf->auto_redirect = 1;
    }

    mlcf->key_index = ngx_http_get_variable_index(cf, &ngx_http_enhanced_memcached_key);

    if (mlcf->key_index == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    mlcf->expire_index = ngx_http_get_variable_index(cf, &ngx_http_enhanced_memcached_expire);

    if (mlcf->expire_index == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    mlcf->use_add_index = ngx_http_get_variable_index(cf, &ngx_http_enhanced_memcached_use_add);

    if (mlcf->use_add_index == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    mlcf->key_namespace_index = ngx_http_get_variable_index(cf, &ngx_http_enhanced_memcached_key_namespace);

    if (mlcf->key_namespace_index == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_enhanced_memcached_variable_not_found(ngx_http_request_t *r,
        ngx_http_variable_value_t *v, uintptr_t data)
{
    v->not_found = 1;
    return NGX_OK;
}


static ngx_int_t
ngx_http_enhanced_memcached_init(ngx_conf_t *cf) {
  ngx_http_variable_t *v;

  v = ngx_http_add_variable(cf, &ngx_http_enhanced_memcached_key, NGX_HTTP_VAR_CHANGEABLE);
  if (v == NULL) {
      return NGX_ERROR;
  }
  v->get_handler = ngx_http_enhanced_memcached_variable_not_found;

  v = ngx_http_add_variable(cf, &ngx_http_enhanced_memcached_expire, NGX_HTTP_VAR_CHANGEABLE);
  if (v == NULL) {
      return NGX_ERROR;
  }
  v->get_handler = ngx_http_enhanced_memcached_variable_not_found;

  v = ngx_http_add_variable(cf, &ngx_http_enhanced_memcached_use_add, NGX_HTTP_VAR_CHANGEABLE);
  if (v == NULL) {
      return NGX_ERROR;
  }
  v->get_handler = ngx_http_enhanced_memcached_variable_not_found;

  v = ngx_http_add_variable(cf, &ngx_http_enhanced_memcached_key_namespace, NGX_HTTP_VAR_CHANGEABLE);
   if (v == NULL) {
       return NGX_ERROR;
  }
  v->get_handler = ngx_http_enhanced_memcached_variable_not_found;

  return NGX_OK;
}
