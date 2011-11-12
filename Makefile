CC=g++
CXXFLAGS=-Wall -Weffc++
LIBS=-lX11 -lXrandr

all: xrr-events

xrr-events: xrr-events.cpp
	$(CC) $(CXXFLAGS) -o$@ $(LIBS) $<

.PHONY:
clean:
	rm xrr-events
