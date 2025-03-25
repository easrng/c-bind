#include <stdio.h>
#include <string.h>
extern void *bind(void *fn, void *arg0);
int main() {
  char *str = "uwu";
  int (*strlen_bound)() = bind(strlen, str);
  printf("length: %d\n", strlen_bound());
}
