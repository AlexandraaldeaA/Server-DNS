MYDNS_SCRIPT = mydns
INSTALL_PATH = /usr/local/bin

.PHONY: all clean 

all:  stop install

stop:
	sudo systemctl stop systemd-resolved

install:
	@if [ -f $(MYDNS_SCRIPT) ]; then \
		chmod +x $(MYDNS_SCRIPT); \
		sudo mv $(MYDNS_SCRIPT) $(INSTALL_PATH); \
	fi

clean:
	sudo rm -f $(INSTALL_PATH)/$(MYDNS_SCRIPT)