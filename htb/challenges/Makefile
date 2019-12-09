TARGET:=challenge
CFLAGS:=-fno-stack-protector -no-pie
TEST_SCRIPT:=./ape.py

.PHONY: all clean test

all: $(TARGET)
clean:
	rm $(TARGET)

$(TARGET): *.c
	$(CC) -o $@ $(CFLAGS) $<

test: $(TARGET)
	-echo "FLAG{TEST_FLAG}" > ./flag.txt
	-$(TEST_SCRIPT) -b $(TARGET) | grep "FLAG{TEST_FLAG}" >/dev/null && echo "Test Success." || echo "Test Failed"
	-rm ./flag.txt