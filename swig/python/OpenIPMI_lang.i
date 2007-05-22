/*
 * OpenIPMI_lang.i
 *
 * Python-specific OpenIPMI SWIG language information
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2004 MontaVista Software Inc.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public License
 *  as published by the Free Software Foundation; either version 2 of
 *  the License, or (at your option) any later version.
 *
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 *  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 *  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 *  OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 *  TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 *  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this program; if not, write to the Free
 *  Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

%typemap(in) swig_cb {
    if ($input == Py_None)
	$1 = NULL;
    else
	$1 = $input;
}

%typemap(arginit) intarray {
    $1.val = NULL;
}

%typemap(in) intarray {
    int i;

    if (!PySequence_Check($input)) {
	PyErr_SetString(PyExc_TypeError,"Expecting a sequence");
	return NULL;
    }
    $1.len = PyObject_Length($input);
    $1.val = (int *) malloc($1.len*sizeof(int));

    for (i=0; i<$1.len; i++) {
	PyObject *o = PySequence_GetItem($input,i);
	if (!o) {
	    PyErr_SetString(PyExc_ValueError, "Expecting a sequence of ints");
	    return NULL;
	}
	if (!PyInt_Check(o)) {
	    free($1.val);
	    PyErr_SetString(PyExc_ValueError,"Expecting a sequence of ints");
	    Py_DECREF(o);
	    return NULL;
	}
	$1.val[i] = PyInt_AS_LONG(o);
	Py_DECREF(o);
    }
}

%typemap(freearg) intarray {
    if ($1.val)
        free($1.val);
};

%typemap(out) intarray {
    PyObject *list;
    int i;

    list = PyList_New($1.len);
    if (!list) {
	PyErr_SetString(PyExc_ValueError,
			"Unable to allocate intarray object");
	return NULL;
    }
    for (i=0; i<$1.len; i++) {
	PyObject *o = PyInt_FromLong($1.val[i]);
	if (!o) {
	    int j;
	    for (j=0; j<i; j++) {
		o = PyList_GetItem(list, j);
		Py_DECREF(o);
	    }
	    Py_DECREF(list);
	    PyErr_SetString(PyExc_ValueError,
			    "Unable to allocate intarray object");
	    return NULL;
	}
	PyList_SET_ITEM(list, i, o);
    }
    $result = list;
}

%typemap(in) argarray * (argarray argval) {
    int i;

    $1 = &argval;
    if (!PySequence_Check($input)) {
	PyErr_SetString(PyExc_TypeError,"Expecting a sequence");
	return NULL;
    }
    $1->len = PyObject_Length($input);
    $1->val = malloc($1->len*sizeof(char *));
    for (i=0; i<$1->len; i++) {
	PyObject *o = PySequence_GetItem($input,i);
	if (!o) {
	    PyErr_SetString(PyExc_ValueError, "Expecting a sequence of strings");
	    return NULL;
	}
	if (!PyString_Check(o)) {
	    PyErr_SetString(PyExc_ValueError,"Expecting a sequence of strings");
	    Py_DECREF(o);
	    return NULL;
	}
	$1->val[i] = PyString_AS_STRING(o);
	Py_DECREF(o);
    }
};

%typemap(argout) argarray {
    /* No output */
}

%typemap(freearg) argarray {
    free($1->val);
};

%typemap(in) iargarray * (iargarray argval) {
    int i;

    $1 = &argval;
    if (!PySequence_Check($input)) {
	PyErr_SetString(PyExc_TypeError,"Expecting a sequence");
	return NULL;
    }
    $1->len = PyObject_Length($input);
    $1->val = malloc($1->len*sizeof(char *));
    for (i=0; i<$1->len; i++) {
	PyObject *o = PySequence_GetItem($input,i);
	if (!o) {
	    PyErr_SetString(PyExc_ValueError, "Expecting a sequence of strings");
	    return NULL;
	}
	SWIG_Python_ConvertPtr(o, (void **)&($1->val[i]),
			       SWIGTYPE_p_ipmi_args_t,
			       SWIG_POINTER_EXCEPTION | 0);
	if (!$1->val[i]) {
	    PyErr_SetString(PyExc_ValueError, "Invalid NULL element");
	    return NULL;
	}
	Py_DECREF(o);
    }
};

%typemap(argout) argarray {
    /* No output */
}

%typemap(freearg) argarray {
    free($1->val);
};

%typemap(in) strconstarray * (strconstarray argval)  {
    $1 = &argval;
    if (!PyList_Check($input)) {
	PyErr_SetString(PyExc_TypeError, "Expecting a list");
	return NULL;
    }
    $1->len = 0;
    $1->val = NULL;
};

%typemap(argout) strconstarray * {
    int i, len;

    len = PySequence_Size($input);
    PySequence_DelSlice($input, 0, len);
    for (i=0; i<$1->len; i++) {
	PyObject *o = PyString_FromString($1->val[i]);
	PyList_Append($input, o);
	Py_DECREF(o);
    }
}

%typemap(freearg) strconstarray * {
  /* holder is const, nothing to do */
};

%typemap(in) double * (double dvalue) {
    PyObject *o;
    if (!PySequence_Check($input)) {
	PyErr_SetString(PyExc_ValueError,"Expecting a sequence");
	return NULL;
    }
    o = PySequence_GetItem($input,0);
    if (!o) {
	PyErr_SetString(PyExc_ValueError, "Expecting a floating point number");
	return NULL;
    }
    if (!PyFloat_Check(o)) {
	Py_DECREF(o);
	PyErr_SetString(PyExc_ValueError, "expected a floating point number");
	return NULL;
    }
    dvalue = PyFloat_AS_DOUBLE(o);
    Py_DECREF(o);
    $1 = &dvalue;
}

%typemap(argout) double * {
    PyObject *o = PyFloat_FromDouble(*$1);
    if (!o) {
	PyErr_SetString(PyExc_TypeError, "Unable to allocate double object");
	return NULL;
    }
    if (PySequence_SetItem($input, 0, o) == -1) {
	PyErr_SetString(PyExc_TypeError, "Unable to set double object item");
	Py_DECREF(o);
	return NULL;
    }
    Py_DECREF(o);
}

%typemap(in) int * (int ivalue) {
    PyObject *o;
    if (!PySequence_Check($input)) {
	PyErr_SetString(PyExc_ValueError, "Expecting a sequence");
	return NULL;
    }
    o = PySequence_GetItem($input, 0);
    if (!o) {
	PyErr_SetString(PyExc_ValueError, "Expecting an integer number");
	return NULL;
    }
    if (!PyInt_Check(o)) {
	Py_DECREF(o);
	PyErr_SetString(PyExc_ValueError, "expected an integer number");
	return NULL;
    }
    ivalue = PyInt_AS_LONG(o);
    Py_DECREF(o);
    $1 = &ivalue;
}

%typemap(argout) int * {
    PyObject *o = PyInt_FromLong(*$1);
    if (!o) {
	PyErr_SetString(PyExc_TypeError, "Unable to allocate int object");
	return NULL;
    }
    if (PySequence_SetItem($input, 0, o) == -1) {
	PyErr_SetString(PyExc_TypeError, "Unable to set int object item");
	Py_DECREF(o);
	return NULL;
    }
    Py_DECREF(o);
}

%typemap(in) unsigned int * (unsigned int ivalue) {
    PyObject *o;
    if (!PySequence_Check($input)) {
	PyErr_SetString(PyExc_ValueError, "Expecting a sequence");
	return NULL;
    }
    o = PySequence_GetItem($input, 0);
    if (!o) {
	PyErr_SetString(PyExc_ValueError, "Expecting an integer number");
	return NULL;
    }
    if (!PyInt_Check(o)) {
	PyErr_SetString(PyExc_ValueError, "expected an integer number");
	Py_DECREF(o);
	return NULL;
    }
    ivalue = PyInt_AS_LONG(o);
    Py_DECREF(o);
    $1 = &ivalue;
}

%typemap(argout) unsigned int * {
    PyObject *o = PyInt_FromLong(*$1);
    if (!o) {
	PyErr_SetString(PyExc_TypeError, "Unable to allocate int object");
	return NULL;
    }
    if (PySequence_SetItem($input, 0, o) == -1) {
	PyErr_SetString(PyExc_TypeError, "Unable to set int object item");
	Py_DECREF(o);
	return NULL;
    }
    Py_DECREF(o);
}

%typemap(in) const char ** (char *svalue) {
    PyObject *o;
    if (!PySequence_Check($input)) {
	PyErr_SetString(PyExc_ValueError, "Expecting a sequence");
	return NULL;
    }
    o = PySequence_GetItem($input, 0);
    if (!o) {
	PyErr_SetString(PyExc_ValueError, "Expecting a string");
	return NULL;
    }
    if (!PyString_Check(o)) {
	Py_DECREF(o);
	PyErr_SetString(PyExc_ValueError, "expected a string");
	return NULL;
    }
    svalue = PyString_AS_STRING(o);
    Py_DECREF(o);
    $1 = &svalue;
}

%typemap(argout) const char ** {
    if (*$1) {
	PyObject *o = PyString_FromString(*$1);
	if (!o) {
	    PyErr_SetString(PyExc_TypeError,
			    "Unable to allocate string object");
	    return NULL;
	}
	if (PySequence_SetItem($input, 0, o) == -1) {
	    PyErr_SetString(PyExc_TypeError,
			    "Unable to set string object item");
	    Py_DECREF(o);
	    return NULL;
	}
	Py_DECREF(o);
    } else {
	if (PySequence_SetItem($input, 0, Py_None) == -1) {
	    PyErr_SetString(PyExc_TypeError,
			    "Unable to set NULL object item");
	    return NULL;
	}
    }
}

%typemap(in) char ** (char *svalue) {
    if (!PySequence_Check($input)) {
	PyErr_SetString(PyExc_ValueError, "Expecting a sequence");
	return NULL;
    }
    svalue = NULL;
    $1 = &svalue;
}

%typemap(argout) char ** {
    if (*$1) {
	PyObject *o = PyString_FromString(*$1);
	if (!o) {
	    PyErr_SetString(PyExc_TypeError, "Unable to allocate string object");
	    return NULL;
	}
	if (PySequence_SetItem($input, 0, o) == -1) {
	    PyErr_SetString(PyExc_TypeError, "Unable to set string object item");
	    Py_DECREF(o);
	    return NULL;
	}
	Py_DECREF(o);
	free(*$1);
    } else {
	if (PySequence_SetItem($input, 0, Py_None) == -1) {
	    PyErr_SetString(PyExc_TypeError,
			    "Unable to set NULL object item");
	    return NULL;
	}
    }
}

%typemap(in) ipmi_fru_node_t ** (ipmi_fru_node_t *pvalue) {
    if (!PySequence_Check($input)) {
	PyErr_SetString(PyExc_ValueError, "Expecting a sequence");
	return NULL;
    }
    pvalue = NULL;
    $1 = &pvalue;
}

%typemap(argout) ipmi_fru_node_t ** {
    if (*$1) {
	PyObject *o = SWIG_NewPointerObj(*$1, SWIGTYPE_p_ipmi_fru_node_t, 1);
	if (!o) {
	    PyErr_SetString(PyExc_TypeError, "Unable to allocate object");
	    return NULL;
	}
	if (PySequence_SetItem($input, 0, o) == -1) {
	    PyErr_SetString(PyExc_TypeError, "Unable to set object item");
	    Py_DECREF(o);
	    return NULL;
	}
	Py_DECREF(o);
    } else {
	if (PySequence_SetItem($input, 0, Py_None) == -1) {
	    PyErr_SetString(PyExc_TypeError,
			    "Unable to set NULL object item");
	    return NULL;
	}
    }
}

%typemap(in) charbuf {
    if (!PyString_Check($input)) {
	PyErr_SetString(PyExc_ValueError, "Expecting a string");
	return NULL;
    }
    PyString_AsStringAndSize($input, &$1.val, &$1.len);
}

%typemap(out) charbuf {
    /* Nothing to do, input only */
};

%{

#if PYTHON_HAS_POSIX_THREADS
#define USE_POSIX_THREADS
#endif

#ifdef WITH_THREAD
#define OpenIPMI_HAVE_INIT_LANG

#if PY_VERSION_HEX < 0x02040000
/* HACK: Only works on POSIX with threads */
#include <pthread.h>

static PyInterpreterState *OI_py_interp;
static pthread_key_t OI_py_key;
struct OI_py_info
{
    int           count;
    PyThreadState *tstate;
};
static void init_lang(void)
{
    PyThreadState *tstate;
    PyEval_InitThreads();
    tstate = PyThreadState_Get();
    OI_py_interp = tstate->interp;
    pthread_key_create(&OI_py_key, NULL);
}
#define OpenIPMI_HAVE_CLEANUP_LANG
static void cleanup_lang(void)
{
    pthread_key_delete(OI_py_key);
    OI_py_key = 0;
}
static int OI_get_py_state()
{
    struct OI_py_info *info;
    int               current = 0;

    info = pthread_getspecific(OI_py_key);
    if (!info) {
	info = malloc(sizeof(*info));
	if (!info)
	    Py_FatalError("OpenIPMI: Could not create thread state");
	info->count = 0;
	info->tstate = PyThreadState_New(OI_py_interp);
	if (!info->tstate)
	    Py_FatalError("OpenIPMI: Could not create thread state");
    } else 
	current = (info->tstate == _PyThreadState_Current);
    if (!current) {
	PyEval_RestoreThread(info->tstate);
	pthread_setspecific(OI_py_key, info);
    }
    info->count++;

    return current;
}
static void OI_put_py_state(int current)
{
    struct OI_py_info *info = pthread_getspecific(OI_py_key);
    if (!info)
	Py_FatalError("OpenIPMI: Releasing thread state, but none present");
    if (info->tstate != _PyThreadState_Current)
	Py_FatalError("OpenIPMI: Releasing incorrect thread state");
    info->count--;
    if (info->count == 0) {
	PyThreadState_Clear(info->tstate);
	pthread_setspecific(OI_py_key, NULL);
	PyThreadState_DeleteCurrent();
	free(info);
    } else if (!current)
	PyEval_SaveThread();
}
#define OI_PY_STATE int
#define OI_PY_STATE_GET() OI_get_py_state()
#define OI_PY_STATE_PUT(s) OI_put_py_state(s)

/* For python, we need to release the GIL when doing something that can
   callback or block, basically any C code with any callback handling. */
#define IPMI_SWIG_C_CB_ENTRY Py_BEGIN_ALLOW_THREADS
#define IPMI_SWIG_C_CB_EXIT Py_END_ALLOW_THREADS
#define IPMI_SWIG_C_BLOCK_ENTRY Py_BEGIN_ALLOW_THREADS
#define IPMI_SWIG_C_BLOCK_EXIT Py_END_ALLOW_THREADS

#else
static void init_lang(void)
{
    PyEval_InitThreads();
}
#define OI_PY_STATE PyGILState_STATE
#define OI_PY_STATE_GET() PyGILState_Ensure()
#define OI_PY_STATE_PUT(s) PyGILState_Release(s)
/* Not required in newer versions of Python, The PyGUILState_Ensure
   does it all for us. */
#define IPMI_SWIG_C_CB_ENTRY 
#define IPMI_SWIG_C_CB_EXIT 

/* We do need to work about blocking, though. */
#define IPMI_SWIG_C_BLOCK_ENTRY Py_BEGIN_ALLOW_THREADS
#define IPMI_SWIG_C_BLOCK_EXIT Py_END_ALLOW_THREADS
#endif
#else
#define OI_PY_STATE int
#define OI_PY_STATE_GET() 0
#define OI_PY_STATE_PUT(s) do { } while(0)

/* No threads */
#define IPMI_SWIG_C_CB_ENTRY 
#define IPMI_SWIG_C_CB_EXIT 
#define IPMI_SWIG_C_BLOCK_ENTRY
#define IPMI_SWIG_C_BLOCK_EXIT
#endif

static swig_ref
swig_make_ref_destruct_i(void *item, swig_type_info *class)
{
    swig_ref    rv;
    OI_PY_STATE gstate;

    gstate = OI_PY_STATE_GET();
    rv.val = SWIG_NewPointerObj(item, class, 1);
    OI_PY_STATE_PUT(gstate);
    return rv;
}

/* Make a reference whose destructor will be called when everything
   is done with it. */
#define swig_make_ref_destruct(item, name) \
	swig_make_ref_destruct_i(item, SWIGTYPE_p_ ## name)

static swig_ref
swig_make_ref_i(void *item, swig_type_info *class)
{
    swig_ref    rv;
    OI_PY_STATE gstate;

    gstate = OI_PY_STATE_GET();
    rv.val = SWIG_NewPointerObj(item, class, 0);
    OI_PY_STATE_PUT(gstate);
    return rv;
}

#define swig_make_ref(item, name) \
	swig_make_ref_i(item, SWIGTYPE_p_ ## name)

static void
swig_free_ref(swig_ref ref)
{
    OI_PY_STATE gstate;

    gstate = OI_PY_STATE_GET();
    Py_DECREF(ref.val);
    OI_PY_STATE_PUT(gstate);
}

static swig_cb_val
get_swig_cb_i(swig_cb cb)
{
    return cb;
}
#define get_swig_cb(cb, func) get_swig_cb_i(cb)

static swig_cb_val
ref_swig_cb_i(swig_cb cb)
{
    OI_PY_STATE gstate;

    gstate = OI_PY_STATE_GET();
    Py_INCREF(cb);
    OI_PY_STATE_PUT(gstate);
    return cb;
}
#define ref_swig_cb(cb, func) ref_swig_cb_i(cb)
#define ref_swig_2cb(cb, func, func2) ref_swig_cb_i(cb)
#define ref_swig_gencb(cb) ref_swig_cb_i(cb)

static swig_cb_val
deref_swig_cb(swig_cb cb)
{
    OI_PY_STATE gstate;

    gstate = OI_PY_STATE_GET();
    Py_DECREF(cb);
    OI_PY_STATE_PUT(gstate);
    return cb;
}

static swig_cb_val
deref_swig_cb_val(swig_cb_val cb)
{
    OI_PY_STATE gstate;

    gstate = OI_PY_STATE_GET();
    Py_DECREF(cb);
    OI_PY_STATE_PUT(gstate);
    return cb;
}

static int
valid_swig_cb_i(swig_cb cb, char *func)
{
    PyObject    *meth;
    OI_PY_STATE gstate;

    gstate = OI_PY_STATE_GET();
    meth = PyObject_GetAttrString(cb, func);
    if (!meth) {
	OI_PY_STATE_PUT(gstate);
	return 0;
    }
    if (!PyMethod_Check(meth)) {
	OI_PY_STATE_PUT(gstate);
	return 0;
    }
    Py_DECREF(meth);
    OI_PY_STATE_PUT(gstate);
    return 1;
}
#define valid_swig_cb(v, func) valid_swig_cb_i(v, #func)
#define valid_swig_2cb(v, func, func2) \
  (valid_swig_cb_i(v, #func) && valid_swig_cb_i(v, #func2))

static int
swig_count_format(char *format)
{
    int count = 0;

    for (; *format; format++) {
	if (*format != '%')
	    continue;
	format++;
	if (*format == '\0')
	    break;
	switch (*format) {
	case 'd':
	case 'f':
	case 's':
	case 'p':
	    count++;
	    break;

	case '*':
	    format++;
	    if (*format == '\0')
		break;
	    switch(*format) {
	    case 's':
	    case 'p':
	    case 'o':
	    case 'b':
		count++;
		break;

	    default:
		break;
	    }
	    break;

	case 'l':
	    format++;
	    if (*format == '\0')
		break;
	    switch(*format) {
	    case 'd':
		count++;
		break;

	    default:
		break;
	    }
	    break;

	default:
	    break;
	}
    }
    return count;
}

static void swig_call_cb(swig_cb_val cb, char *method_name, char *format, ...)
#ifdef __GNUC__
     __attribute__ ((__format__ (__printf__, 3, 4)))
#endif
;
static void swig_call_cb_rv(char rv_type, void *rv,
			    swig_cb_val cb, char *method_name,
			    char *format, ...)
#ifdef __GNUC__
     __attribute__ ((__format__ (__printf__, 5, 6)))
#endif
;
static void
vswig_call_cb_rv(char rv_type, void *rv,
		 swig_cb_val cb, char *method_name,
		 char *format, va_list ap)
{
    int           len;
    unsigned char *data;
    int           *idata;
    PyObject      *args = NULL;
    int           n;
    int           i;
    int           pos;
    char          *errstr;
    PyObject      *o = NULL;
    PyObject      *p;
    OI_PY_STATE   gstate;

    gstate = OI_PY_STATE_GET();

    n = swig_count_format(format);

    args = PyTuple_New(n);
    if (!args) {
	errstr = "cannot allocate PyTyple";
	goto out_err;
    }

    pos = 0;
    for (; *format; format++) {
	if (*format != '%')
	    continue;
	format++;
	if (*format == '\0')
	    break;
	o = NULL;
	switch (*format) {
	case 'd':
	    o = PyInt_FromLong(va_arg(ap, int));
	    break;

	case 'f':
	    o = PyFloat_FromDouble(va_arg(ap, double));
	    break;

	case '*':
	    format++;
	    if (*format == '\0')
		break;
	    switch(*format) {
	    case 's':
		/* An array of unsigned characters */
		len = va_arg(ap, int);
		data = va_arg(ap, unsigned char *);
		o = PyList_New(len);
		if (!o) {
		    errstr = "cannot allocate list";
		    goto out_err;
		}
		for (i=0; i<len; i++, data++) {
		    p = PyInt_FromLong(*data);
		    if (!p) {
			errstr = "cannot allocate uchar list item";
			goto out_err;
		    }
		    PyList_SET_ITEM(o, i, p);
		}
		break;

	    case 'b':
		/* An array characters with length, as chars.  May
		   include nuls */
		len = va_arg(ap, size_t);
		data = va_arg(ap, void *);
		o = PyString_FromStringAndSize(data, len);
		break;

	    case 'p':
		/* An array of integers */
		len = va_arg(ap, int);
		idata = va_arg(ap, int *);
		o = PyList_New(len);
		if (!o) {
		    errstr = "cannot allocate list";
		    goto out_err;
		}
		for (i=0; i<len; i++, idata++) {
		    p = PyInt_FromLong(*idata);
		    if (!p) {
			errstr = "cannot allocate uchar list item";
			goto out_err;
		    }
		    PyList_SET_ITEM(o, i, p);
		}
		break;

	    case 'o':
		/* An array of objects */
		{
		    swig_ref *list;
		    len = va_arg(ap, int);
		    list = va_arg(ap, swig_ref *);
		    o = PyList_New(len);
		    if (!o) {
			errstr = "cannot allocate list";
			goto out_err;
		    }
		    for (i=0; i<len; i++, list++)
			PyList_SET_ITEM(o, i, list->val);
		}
		break;

	    default:
		break;
	    }
	    break;

	case 'l':
	    format++;
	    if (*format == '\0')
		break;
	    switch(*format) {
	    case 'd':
		/* Long int */
		o = PyInt_FromLong(va_arg(ap, long));
		break;

	    default:
		break;
	    }
	    break;
	    
	case 's':
	    /* String */
	    o = PyString_FromString(va_arg(ap, char *));
	    break;

	case 'p':
	    /* Object pointer (swig_ref) */
	    {
		swig_ref *v = va_arg(ap, swig_ref *);
		o = v->val;
		/* Create a ref for setting the item, since python
		   doesn't do that. */
		Py_INCREF(o);
	    }
	    break;

	default:
	    break;
	}

	if (!o) {
	    errstr = "Problem getting object";
	    goto out_err;
	}

	PyTuple_SET_ITEM(args, pos, o);
	o = NULL;
	pos++;
    }

    p = PyObject_GetAttrString(cb, method_name);
    if (p) {
	o = PyObject_CallObject(p, args);
	Py_DECREF(p);
	if (rv) {
	    switch (rv_type) {
	    case 'i': /* Integer */
		*((int *) rv) = PyInt_AsLong(o);
		break;

	    case 'I': /* Integer, no return value leave alone */
		if (o && (o != Py_None))
		    *((int *) rv) = PyInt_AsLong(o);
		break;

	    default:
		Py_FatalError("OpenIPMI: Invalid return type specified");
		break;
	    }
	}
	if (o) {
	    Py_DECREF(o);
	}
	if (PyErr_Occurred()) {
	    fprintf(stderr, "Error from %s\n", method_name);
	    PyErr_Print();
	}
    }
    Py_DECREF(args);

    OI_PY_STATE_PUT(gstate);
    return;

 out_err:
    PyErr_SetString(PyExc_TypeError, errstr);
    PyErr_Print();
    if (o) {
	Py_DECREF(o);
    }
    OI_PY_STATE_PUT(gstate);
}

static void
swig_call_cb(swig_cb_val cb, char *method_name,
	     char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    vswig_call_cb_rv(' ', NULL, cb, method_name, format, ap);
    va_end(ap);
}

static void
swig_call_cb_rv(char rv_type, void *rv,
		swig_cb_val cb, char *method_name,
		char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    vswig_call_cb_rv(rv_type, rv, cb, method_name, format, ap);
    va_end(ap);
}

%}
