#include "dr_api.h"
// #include "utils.h"
#include "drwrap.h"
#include "drmgr.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <dr_showcase.h>

static void wrap_encrypt_string(void *wrapcxt,  void **user_data);

static void *max_lock; 

static void
module_load_event(void *drcontext, const module_data_t *mod, bool loaded)
{
    printf("PATH= %s\n", mod->full_path);

    app_pc towrap = (app_pc)dr_get_proc_address(mod->handle, "encrypt_string");
    if (towrap != NULL) {
        
        bool ok = drwrap_wrap(towrap, wrap_encrypt_string, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn't get encrypt_string\n");
        }

    }
    
}

static void
event_exit(void)
{
    printf("IN EXIT\n");
    drwrap_exit();
    drmgr_exit();
}

DR_EXPORT void
dr_init(client_id_t id)
{
    /* make it easy to tell, by looking at log file, which client executed */
    dr_log(NULL, DR_LOG_ALL, 1, "Client initializing\n");

    if (dr_is_notify_on()) {
        dr_fprintf(STDERR, "Client running! See test.log!\n");
    }

    printf("IN AT START OF INIT\n");

    drmgr_init();
    drwrap_init();
    dr_register_exit_event(event_exit);
    drmgr_register_module_load_event(module_load_event);
    max_lock = dr_mutex_create();
}


static void wrap_encrypt_string(void *wrapcxt,  void **user_data){

	dr_mutex_lock(max_lock);
	printf("IN encrypt_string\n");
	dr_mutex_unlock(max_lock);


    void *which = (void *)drwrap_get_arg(wrapcxt, 0);


    char filename[128] = { 0 };
    dr_snprintf(filename, 128, "test.log");

    char buf[512];

    
    filename[511] = '\0';
    dr_mutex_lock(max_lock);
    FILE *fp = fopen(filename, "ab+");

    if (!fp) {
        dr_fprintf(STDERR, "Couldn’t open the output file %s\n", filename);
        return;
    }
    //write the arguments to the function to a file.
    fwrite(which, 1, 512, fp);
    fclose(fp);
    dr_mutex_unlock(max_lock);
} 
