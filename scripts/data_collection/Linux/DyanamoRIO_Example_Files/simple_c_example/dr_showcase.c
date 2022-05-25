#include <dr_showcase.h>

typedef void (*lib_func)();



int call_library()
{  
   char __unnamed[] = "HELLO\0";
   char* test_string = __unnamed;

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
   while(1){ 
    printf("ENCRYPTED STRING %s\n",test_string);
    func(test_string,5);
    sleep(1);

   }
   return 0;
}



int main(){

    call_library();
    
    return 0;
}