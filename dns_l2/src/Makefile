MODNAME = sdns_l2
obj-m +=sdns_l2.o

# -objs's name can not same with obj-m, or well call "module license 'unspecified' taints kernel."
# $(MODNAME)-objs += sdns_l2.o str.o  #sdns_l2.o is same to obj-m's file, it is bad file name.
$(MODNAME)-objs += sdns_intercept.o str.o 
