src := qcert.cc
flags := -Iinclude -lcrypto -DDEBUG

qcert : $(src)
	g++ -o qcert $(src) -std=c++11 $(flags)

run: qcert
	./qcert xbl.img

.PHONY: clean
clean:
	rm qcert
