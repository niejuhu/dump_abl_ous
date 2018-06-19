src := qcert.cc
flags := -Iinclude -lcrypto

qcert : $(src)
	g++ -o qcert $(src) -std=c++11 $(flags)

run: qcert
	./qcert xbl.img

.PHONY: clean
clean:
	rm qcert
