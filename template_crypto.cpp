/* Copyright (C) 2020 D8DATAWORKS - All Rights Reserved */

#ifdef TEST_RUNNER


#define CATCH_CONFIG_RUNNER
#include "catch.hpp"
#include "tcrypt/test.hpp"

int main(int argc, char* argv[])
{
    return Catch::Session().run(argc, argv);
}

#else

#endif //TEST_RUNNER