
typedef void *swig_cb;
typedef void *swig_ref;

swig_cb ref_swig_cb(swig_cb cb);
swig_cb deref_swig_cb(swig_cb cb);

void swig_call_cb(swig_cb cb, char *method_name, char *format, ...)
#ifdef __GNUC__
     __attribute__ ((__format__ (__printf__, 3, 4)))
#endif
;

swig_ref swig_make_ref(void *item, char *name);
void swig_free_ref(swig_ref ref);
