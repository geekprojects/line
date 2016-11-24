
#include <stdlib.h>

#include "line.h"

int main(int argc, char** argv)
{
if (argc != 2)
{
printf("%s <executable>\n", argv[0]);
exit(1);
}
    Line line;
    line.open(argv[1]);
    line.execute();
    return 0;
}

