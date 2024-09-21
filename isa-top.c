#include <stdlib.h>
#include <stdio.h>
#include <ncurses.h>

int main(){
    printf("ncurse verze: %d, %d,%d\n", NCURSES_VERSION_MAJOR,
                                    NCURSES_VERSION_MINOR,
                                    NCURSES_VERSION_PATCH);
    return 0;
}