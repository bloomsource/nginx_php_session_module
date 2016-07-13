#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>



typedef struct {
    ngx_flag_t check;
    ngx_str_t  save_path;
    ngx_uint_t save_depth;
    ngx_str_t  cookie;
    ngx_str_t  key;
    ngx_uint_t retcode;
} ngx_http_php_session_loc_conf_t;

static char* ngx_http_php_session(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void* ngx_http_php_session_create_loc_conf(ngx_conf_t* cf);

static char* ngx_http_php_session_merge_loc_conf(ngx_conf_t* cf, void* parent, void* child);

static int str_split( char* str, char delimiter, char* fields[], int size, int* count );

//int write_log( const char* fmt, ... );

//char log_file[] = "/tmp/ngx_php_session.log";


static ngx_command_t ngx_http_php_session_commands[] = {
    {
        ngx_string( "php_session_check" ),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_http_php_session,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_php_session_loc_conf_t, check),
        NULL
    },
    {
        ngx_string( "php_session_save_path" ),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_php_session_loc_conf_t, save_path),
        NULL
    },
    {
        ngx_string( "php_session_save_depth" ),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_php_session_loc_conf_t, save_depth),
        NULL
    },
    {
        ngx_string( "php_session_cookie" ),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_php_session_loc_conf_t, cookie),
        NULL
    },
    {
        ngx_string( "php_session_key" ),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_php_session_loc_conf_t, key),
        NULL
    },
    {
        ngx_string( "php_session_retcode" ),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_php_session_loc_conf_t, retcode),
        NULL
    },
    ngx_null_command
};


static ngx_http_module_t ngx_http_php_session_module_ctx = {
    NULL,
    NULL, //ngx_http_authctl_init,
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_http_php_session_create_loc_conf,
    ngx_http_php_session_merge_loc_conf
};


ngx_module_t ngx_http_php_session_module = {
    NGX_MODULE_V1,
    &ngx_http_php_session_module_ctx,
    ngx_http_php_session_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};

int session_file( char* file, int size, char* save_path, int path_len , char* session, int depth )
{
    int i;
    char* f;
    
    if( ( path_len + 1 + depth*2  +strlen( session ) + 1 ) > (unsigned int)size )
        return -1;
    
    if( save_path[path_len-1] == '/' )
        sprintf( file, "%.*s", path_len, save_path );
    else
        sprintf( file, "%.*s/", path_len, save_path );
    
    f = file + strlen( file );
    if( depth )
    {
        for( i = 0; i < depth; i++ )
        {
            f[i*2] = session[i];
            f[i*2+1] = '/';
        }
        
        f += depth*2;
    }
    
    sprintf( f, "sess_%s", session );
    
    return 0;
}

static ngx_int_t ngx_http_php_session_handler(ngx_http_request_t* r) {
    char file[200];
    char tmp[500];
    char session[30];
    char* flds[20];
    int count;
    char* p;
    int i;
    
    size_t rc;
    ngx_str_t value;
    FILE* f;
    
    //write_log( "ngx_http_php_session_handler()" );
    
    ngx_http_php_session_loc_conf_t* lcf;
    lcf = ngx_http_get_module_loc_conf( r, ngx_http_php_session_module );
    
    /*write_log( "check: %d, save_path: %.*s, save_depth: %d, cookie:%.*s, key:%.*s, retcode:%d", 
               lcf->check, (int)lcf->save_path.len, lcf->save_path.data, lcf->save_depth, 
               (int)lcf->cookie.len, lcf->cookie.data, (int)lcf->key.len, lcf->key.data, 
               lcf->retcode );
    */
    
    if( !lcf->check )
        return NGX_DECLINED;
    
    if( ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &lcf->cookie, &value ) == NGX_DECLINED )
        return lcf->retcode;
    
    if( value.len == 0 )
        return lcf->retcode;
    
    snprintf( session, sizeof(session), "%.*s", (int)value.len, value.data );
    
    //write_log( "session: %s", session );
    
    if( session_file( file, sizeof(file), (char*)lcf->save_path.data, (int)lcf->save_path.len, session, lcf->save_depth ) )
        return lcf->retcode;
    
    //write_log( "session file: %s", file );
    
    f = fopen( file, "r" );
    if( !f )
        return lcf->retcode;
    
    rc = fread( tmp, 1, sizeof(tmp)-1, f );
    if( rc == 0 )
    {
        fclose( f );
        return lcf->retcode;
    }
    fclose( f );
    
    tmp[rc] = 0;
    if( str_split( tmp, ';', flds, 20, &count ) )
        return lcf->retcode;

    for( i = 0; i < count; i++ )
    {
        p = strchr( flds[i], '|' );
        if( !p )
            return lcf->retcode;
        p[0] = 0;
        
        if( ( strlen( flds[i] ) == (unsigned int) lcf->key.len ) && ( !memcmp( flds[i], lcf->key.data, lcf->key.len ) ) )
            return NGX_DECLINED;
    }
    
    return lcf->retcode;
    
}


static void* ngx_http_php_session_create_loc_conf(ngx_conf_t* cf) {
    ngx_http_php_session_loc_conf_t* conf;
    
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_php_session_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    
    conf->check = NGX_CONF_UNSET_UINT;
    
    conf->save_path.len = 0;
    conf->save_path.data = NULL;
    
    conf->save_depth = NGX_CONF_UNSET_UINT;
    
    conf->cookie.len = 0;
    conf->cookie.data = NULL;
    
    conf->key.len = 0;
    conf->key.data = NULL;
    
    conf->retcode = NGX_CONF_UNSET_UINT;
    
    return conf;
}

static char* ngx_http_php_session_merge_loc_conf(ngx_conf_t* cf, void* parent, void* child) {
    ngx_http_php_session_loc_conf_t* prev = parent;
    ngx_http_php_session_loc_conf_t* conf = child;

    ngx_conf_merge_value( conf->check, prev->check, 1 );
    ngx_conf_merge_str_value( conf->save_path, prev->save_path, "/tmp");
    ngx_conf_merge_uint_value( conf->save_depth, prev->save_depth, 0 );
    ngx_conf_merge_str_value( conf->cookie, prev->cookie, "PHPSESSID");
    ngx_conf_merge_str_value( conf->key, prev->key, "user");
    ngx_conf_merge_uint_value( conf->retcode, prev->retcode, NGX_HTTP_FORBIDDEN );
    
    return NGX_CONF_OK;
}


static char* ngx_http_php_session(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_php_session_handler;

    ngx_conf_set_str_slot(cf, cmd, conf);

    return NGX_CONF_OK;
}

static int str_split( char* str, char delimiter, char* fields[], int size, int* count )
{
    char* source;
    char* p;
    int cnt = 0;
    
    source = str;
    while( *source )
    {
        p = strchr(source, delimiter );
        if( !p )
        {
            if( cnt+1 > size ) return -1; // not enough space of holds
            fields[cnt] = source;
            cnt++;
            break;
        }
        else
        {
            *p = 0;
            if( cnt+1 > size ) return -1; // not enough space of holds
            fields[cnt] = source;
            source = p+1;
            cnt++;
        }
    }

    *count = cnt;
    
    return 0;
}

/*
int write_log( const char* fmt, ... )
{
    FILE* f;
    time_t t;
    struct tm* tm;
    va_list  ap;
    //struct timeval tmv;

    f = fopen( log_file, "a" );
    if( f == NULL )
        return -1;
    
    t = time( 0 );
    //gettimeofday( &tmv, NULL );
    
    tm = localtime( &t );
    
    if( *fmt )
    {
        va_start( ap, fmt );
        //fprintf(f,"[%02d-%02d %02d:%02d:%02d.%03d]  ",tm->tm_mon+1,tm->tm_mday,tm->tm_hour,tm->tm_min,tm->tm_sec,tmv.tv_usec / 1000 );
        fprintf( f, "[%02d-%02d %02d:%02d:%02d]  ", tm->tm_mon+1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec );
        vfprintf( f, fmt, ap);
        fprintf( f, "\n" );
        va_end( ap );
    }
    
    fclose( f );
    return 0;
}

//*/