
/* A callback object.  Note that this is the one that will be passed
   in by the user.  For Perl, we want the real reference, which is a
   swig_cb_val. */
typedef SV *swig_cb;

/* The real underlying reference to the callback object.  This should
   always be a pointer. */
typedef SV *swig_cb_val;

/* Get the underlying callback object reference. */
swig_cb_val get_swig_cb(swig_cb cb);

/* Get the underlying callback object reference and increment its refcount. */
swig_cb_val ref_swig_cb(swig_cb cb);

/* Get the underlying callback object reference and decrement its refcount. */
swig_cb_val deref_swig_cb(swig_cb cb);

/* Decrement the underlying callback object refcount. */
swig_cb_val deref_swig_cb_val(swig_cb_val cb);

/* Used to validate the CB values passed in by the user. */
#define valid_swig_cb(v) ((v) && (SvOK(v)) && (SvOK(SvRV(v))))
#define invalidate_swig_cb(v) ((v) = NULL)


void swig_call_cb(swig_cb_val cb, char *method_name, char *format, ...)
#ifdef __GNUC__
     __attribute__ ((__format__ (__printf__, 3, 4)))
#endif
;


typedef struct swig_ref
{
    SV *val;
} swig_ref;


swig_ref swig_make_ref(void *item, char *name);
void swig_free_ref(swig_ref ref);
