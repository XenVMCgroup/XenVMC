# To build modules outside of the kernel tree, we run "make"
# in the kernel source tree; the Makefile there then includes this
# Makefile once again.


# This conditional selects whether we are being included from the
# kernel Makefile or not.
ifeq ($(KERNELRELEASE),)

	# Assume the source tree is where the running kernel was built
	# You should set KERNELDIR in the environment if it's elsewhere
	KERNELDIR ?= /lib/modules/$(shell uname -r)/build

	# The current directory is passed to sub-makes as argument
	PWD := $(shell pwd)

modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

modules_install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install

clean:
	rm -rf *.o *~ *# *.symvers core .depend .*.cmd *.ko *.mod.c .tmp_versions

.PHONY: modules modules_install clean

else
	xenvmc_frontend-objs :=  xenfifo.o maptable.o bififo.o main.o
	obj-m :=  xenvmc_backend.o xenvmc_frontend.o
endif

define all_sources
    ( find -name '*.[chS]' -print )
endef

define set_exuberant_flags
    exuberant_flags=`$1 --version 2>/dev/null | (grep -iq exuberant && \
	echo "-I __initdata,__exitdata,__acquires,__releases \
	    -I EXPORT_SYMBOL,EXPORT_SYMBOL_GPL \
	    --extra=+f --c-kinds=+px") || true` 
endef
.PHONY: _tags all
all:
	$(MAKE) modules
	cp -f xenvmc_frontend.ko /home/public/
_tags: 
	set -e; rm -f tags; \
	$(call set_exuberant_flags,ctags); \
	$(all_sources) | xargs ctags $$exuberant_flags -a

_cscope:
	$(all_sources) > cscope.files
	cscope -k -b -q
copy:
	cp xenvmc_frontend.ko /home/samba
