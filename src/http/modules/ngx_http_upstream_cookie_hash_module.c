
/*
 * Copyright (C) ongonginging@gmail.com
 * Copyright (C) www.hichao.com 
 */

#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    /* the round robin data must be first */
    ngx_http_upstream_rr_peer_data_t   rrp;

    ngx_uint_t                         hash;

    u_char                             sess_id[32];

    u_char                             tries;

    ngx_event_get_peer_pt              get_rr_peer;
} ngx_http_upstream_cookie_hash_peer_data_t;

static ngx_int_t ngx_http_upstream_init_cookie_hash_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_get_cookie_hash_peer(ngx_peer_connection_t *pc,
    void *data);
static char *ngx_http_upstream_cookie_hash(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_command_t  ngx_http_upstream_cookie_hash_commands[] = {

    { ngx_string("cookie_hash"),
      NGX_HTTP_UPS_CONF|NGX_CONF_NOARGS,
      ngx_http_upstream_cookie_hash,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_upstream_cookie_hash_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};

ngx_module_t  ngx_http_upstream_cookie_hash_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_cookie_hash_module_ctx, /* module context */
    ngx_http_upstream_cookie_hash_commands,    /* module directives */
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

static void kmp_get_next(ngx_http_request_t *r, const char * t, int * next){
    int k = -1; 
    int j = 0;
    int size = 0;
    if(t == NULL || next == NULL){
        ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "kmp error 4");
        return;
    }   
    size = strlen(t);

    next[0] = -1; 
    while(j < size){
        if((k == -1) || (t[j] == t[k])){
            k++;
            j++;
            next[j] = k;
        }else{
            k = next[k];
        }   
    }   
}

static int kmp(ngx_http_request_t *r, const char * dst,const char * sub){    
    int dst_size = 0;
    int sub_size = 0;
    int * next = NULL;
    int i = 0;
    int j = 0;

    if( dst == NULL ||sub == NULL){
        ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "kmp error 1");
        return -1; 
    }   
    dst_size = strlen(dst);
    sub_size = strlen(sub);

    next = (int *)(malloc(sizeof(int) * sub_size));
    if(next == NULL){
        ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "kmp error 2");
        return -1; 
    }   

    assert((dst != NULL) && ( sub != NULL));
    kmp_get_next(r, sub, next);
    while((i < dst_size) && (j < sub_size)){
        if((j == -1) || (dst[i] == sub[j])){    
            i++;    
            j++;    
        }else{
            j = next[j];    
        }   
    }   
    free(next);
    if( j == sub_size) {
        return i - j;
    }   
    ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "kmp error 3");
    return -1; 
}

static int get_session_id(ngx_http_request_t *r, const char* cookie, const char* key, char* value){
    if (cookie == NULL || key == NULL){
        ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "get_session_id error 1");
        return -1; 
    }   
    int key_len = strlen(key);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "cookie = %s", cookie);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "key = %s", key);
    int key_start = kmp(r, cookie, key);
    if (key_start == -1){
        ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "get_session_id error 2");
        return -1;
    }   
    int key_end = key_start + key_len;
    char* p=(char *)cookie + key_end;
    while(*p != '\0'){
        if (*p == ' '|| *p == '='){
            p++;
        }else{
            break;
        }   
    }   
    if (*p == '\0') {
        ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "get_session_id error 3");
        return -1;
    }   
    char* pvalue_start = p;
    while(*p != '\0'){
        if (*p == ' '|| *p == ';'){
            break;
        }else{
            p++;
        }   
    }   
    char* pvalue_end = p;
    int value_len = pvalue_end - pvalue_start;
    if (value_len == 0){
        ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "get_session_id error 4");
        return -1;
    }
    if (value_len > 32){
        ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "get_session_id error 5");
        return -1;
    }
    memcpy(value, pvalue_start, value_len);
    return 0;
}

static ngx_int_t
ngx_http_upstream_init_cookie_hash(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us)
{
	
    if (ngx_http_upstream_init_round_robin(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    us->peer.init = ngx_http_upstream_init_cookie_hash_peer;
	
    return NGX_OK;
}

static ngx_int_t
ngx_http_upstream_init_cookie_hash_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_table_elt_t** cookies;
    ngx_http_upstream_cookie_hash_peer_data_t  *ckhp;

    ngx_uint_t i;

    ckhp = ngx_palloc(r->pool, sizeof(ngx_http_upstream_cookie_hash_peer_data_t));
    if (ckhp == NULL) {
        return NGX_ERROR;
    }
    ngx_memset(ckhp->sess_id, 0, sizeof(ckhp->sess_id));


    r->upstream->peer.data = &ckhp->rrp;

    if (ngx_http_upstream_init_round_robin_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }
    r->upstream->peer.get = ngx_http_upstream_get_cookie_hash_peer;

    cookies = r->headers_in.cookies.elts;
    for(i=0; i<r->headers_in.cookies.nelts; i++) {
        if (0 == ngx_strcmp((u_char*)"Cookie", cookies[i]->key.data)){
            if(0 == get_session_id(r, (char*)cookies[i]->value.data, "PHPSESSID", (char*)ckhp->sess_id)){
                if (strlen((char*)ckhp->sess_id)>0){
                    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "session id: %s", ckhp->sess_id);
                    break;
                }
            }
        }
    }
    
    ckhp->hash = 89;
    ckhp->tries = 0;
    ckhp->get_rr_peer = ngx_http_upstream_get_round_robin_peer;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_get_cookie_hash_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_cookie_hash_peer_data_t  *ckhp = data;

    time_t                        now;
    ngx_int_t                     w;
    uintptr_t                     m;
    ngx_uint_t                    i, n, p, hash;
    ngx_http_upstream_rr_peer_t  *peer;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get ip hash peer, try: %ui", pc->tries);

    /* TODO: cached */

    if (ckhp->tries > 20 || ckhp->rrp.peers->single) {
        return ckhp->get_rr_peer(pc, &ckhp->rrp);
    }

    now = ngx_time();

    pc->cached = 0;
    pc->connection = NULL;

    hash = ckhp->hash;

    ngx_uint_t sess_id_len = sizeof(ckhp->sess_id);

    for ( ;; ) {

        for (i = 0; i < sess_id_len; i++) {
            hash = (hash * 113 + ckhp->sess_id[i]) % 6271;
        }

        if (!ckhp->rrp.peers->weighted) {
            p = hash % ckhp->rrp.peers->number;

        } else {
            w = hash % ckhp->rrp.peers->total_weight;

            for (i = 0; i < ckhp->rrp.peers->number; i++) {
                w -= ckhp->rrp.peers->peer[i].weight;
                if (w < 0) {
                    break;
                }
            }

            p = i;
        }

        n = p / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

        if (ckhp->rrp.tried[n] & m) {
            goto next;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "get cookie hash peer, hash: %ui %04XA", p, m);

        peer = &ckhp->rrp.peers->peer[p];

        /* ngx_lock_mutex(ckhp->rrp.peers->mutex); */

        if (peer->down) {
            goto next_try;
        }

        if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout)
        {
            goto next_try;
        }

        break;

    next_try:

        ckhp->rrp.tried[n] |= m;

        /* ngx_unlock_mutex(ckhp->rrp.peers->mutex); */

        pc->tries--;

    next:

        if (++ckhp->tries > 20) {
            return ckhp->get_rr_peer(pc, &ckhp->rrp);
        }
    }

    ckhp->rrp.current = p;

    pc->sockaddr = peer->sockaddr;
    pc->socklen = peer->socklen;
    pc->name = &peer->name;

    if (now - peer->checked > peer->fail_timeout) {
        peer->checked = now;
    }

    /* ngx_unlock_mutex(ckhp->rrp.peers->mutex); */

    ckhp->rrp.tried[n] |= m;
    ckhp->hash = hash;

    return NGX_OK;
}

static char *
ngx_http_upstream_cookie_hash(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_srv_conf_t  *uscf;

    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

    if (uscf->peer.init_upstream) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "load balancing method redefined");
    }

    uscf->peer.init_upstream = ngx_http_upstream_init_cookie_hash;

    uscf->flags = NGX_HTTP_UPSTREAM_CREATE
                  |NGX_HTTP_UPSTREAM_WEIGHT
                  |NGX_HTTP_UPSTREAM_MAX_FAILS
                  |NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
                  |NGX_HTTP_UPSTREAM_DOWN;

    return NGX_CONF_OK;
}
