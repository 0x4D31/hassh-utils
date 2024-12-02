# Sat Sep 16 22:26:18 CEST 2023
# devnull@libcrack.so

NMAP_FILES = ssh-hassh.nse hasshdb
ALL_FILES   := $(foreach f,$(NMAP_FILES),$(addprefix $(NMAP_DIR)/,$(f)))

ifeq ($(shell uname -s), Linux)
NMAP_DB_DIR=/usr/share/nmap/nselib/data
NMAP_SC_DIR = /usr/share/nmap/scripts
else
ifeq  ($(shell uname -s), Darwin)
NMAP_DB_DIR=/usr/local/share/nmap/nselib/data
NMAP_SC_DIR = /usr/local/share/nmap/scripts
endif
endif


default:
	echo "Usage: make <install|uninstall|docker>"

docker:
	docker build -t hassh:latest .

install:
	install -m 0644 -t $(NMAP_DB_DIR) hasshdb
	install -m 0644 -t $(NMAP_SC_DIR) ssh-hassh.nse

uninstall:
	rm $(NMAP_DB_DIR)/hasshdb
	rm $(NMAP_SC_DIR)/ssh-hassh.nse

.SILENT: default
