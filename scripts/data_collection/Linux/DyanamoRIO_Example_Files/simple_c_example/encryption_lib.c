#include "encryption_lib.h"
#include <dlfcn.h>
#include <stdio.h>

void encrypt_string(char* plaintext, char key){
    for(int i =0; plaintext[i] != 0; i+=1){
        plaintext[i] = plaintext[i] ^ key;
    }
}

void unexported_callback() /*< Function we don't want to export */
{
    printf("Hello from unexported callback!\n");
}

typedef void (*lib_func)();

int call_library()
{
   void     *handle  = NULL;
   lib_func  func    = NULL;
   handle = dlopen("./ec_lib.so", RTLD_NOW | RTLD_GLOBAL);
   if (handle == NULL)
   {
       fprintf(stderr, "Unable to open lib: %s\n", dlerror());
       return -1;
   }
   func = dlsym(handle, "encrypt_string");

   if (func == NULL) {
       fprintf(stderr, "Unable to get symbol\n");
      return -1;
   }

   func();
   return 0;
}

int main(int argc, const char *argv[])
{
    printf("Hello from main!\n");
    call_library();
    return 0;
}