src := qcert.cc
flags := -Iinclude -lcrypto

qcert : $(src)
	g++ -o qcert -std=c++11 $(flags) $(src)

run: qcert
	./qcert xbl.img

.PHONY: clean
clean:
	rm qcert
