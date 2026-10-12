// The app is written in Rust (crates/app); Xcode links it as a static
// library and this starts it.
extern void twosecret_main(void);

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    twosecret_main();
    return 0;
}
