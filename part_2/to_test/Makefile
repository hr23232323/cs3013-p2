all: procAncestry

procAncestry: procAncestry.o
	gcc -pthread procAncestry.o -o procAncestry

procAncestry.o: procAncestry.c
	gcc -g -c procAncestry.c


clean:
	rm -f *.o procAncestry
