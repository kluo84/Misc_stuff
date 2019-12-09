#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NCOMMANDS 4

typedef void(*command_func_t)(void);

void win( void );
void do_register( void );
void do_login( void );
void do_quit( void );
void do_help( void );
size_t read_string(char* s, size_t size);

// Encryption Key
char key[64] = {13,31,230,16,54,10,159,232,40,59,76,216,27,207,155,236,159,173,144,236,24,133,191,129,21,125,238,119,191,79,34,72,254,74,241,199,125,207,87,205,91,195,35,155,112,180,98,28,60,19,43,156,1,18,86,81,68,81,155,134,164,170,159,245};
//char key[65] = {10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,0};
// Username and (encrypted) password for authentication
char g_username[64] = {0,1};
char g_password[32] = {0,1};
// Commands available to run
command_func_t commands[NCOMMANDS] = {
    do_quit,
    do_help,
    do_register,
    do_login
};
const char* command_names[NCOMMANDS] = {
    "quit",
    "help",
    "register",
    "login"
};

int main(int argc, char** argv)
{
    char input[64];
    size_t len;

    // Disable buffering on stdout
    setvbuf(stdout, NULL, _IONBF, 0);

    puts("*** Authentication Portal v1.0 (Beta) ***");
    puts("Type \"help\" for a list of commands");

    while( 1 )
    {
        // Read command
        printf("> ");
        len = read_string(input, 64);

        // Ignore empty commands
        if( len == 0 ) continue;

        // Store the command we find
        command_func_t func = NULL;

        // Search for a matching command
        for(int i = 0; i < NCOMMANDS; ++i){
            if( strcmp(command_names[i], input) == 0 ){
                func = commands[i];
            }
        }

        // Execute it
        if( func == NULL ){
            fprintf(stderr, "error: %s: invalid command (try 'help')\n", input);
        } else {
            func();
        }
        
    }

    return 0;
}

size_t read_string(char* s, size_t size)
{
    fgets(s, size, stdin);
    size_t len = strlen(s);
    if( len > 0 && s[len-1] == '\n' ){
        s[--len] = 0;
    }
    return len;
}

void do_help( void )
{
    puts("available commands:");
    for(int i = 0; i < NCOMMANDS; ++i){
        printf("\t%s\n", command_names[i]);
    }
}

void do_register( void )
{
    // Read in new credentials
    printf("New Username: ");
    read_string(g_username, 64);
    printf("New Password: ");
    read_string(g_password, 64);

    // Don't store passwords in plaintext!
    for(size_t i = 0; i < strlen(g_password); ++i){
        g_password[i] = g_password[i] ^ key[i];
    }
}

void do_login( void )
{
    char password[64];
    char username[64];

    if( g_password[0] == 0 ){
        fprintf(stderr, "error: please register first.\n");
        return;
    }

    // Read username
    printf("Username: ");
    read_string(username, 64);

    // Check username against password
    if( strcmp(username, g_username) != 0 ){
        fprintf(stderr, "error: user %s does not exist!\n", username);
        return;
    }

    // Read password
    printf("Password: ");
    read_string(password, 64);

    // Encrypt password
    for(size_t i = 0; i < strlen(password); i++){
        password[i] ^= key[i];
    }

    // Check password against stored password
    if( strcmp(g_password, password) != 0 ){
        fprintf(stderr, "error: invalid password for user %s!\n", username);
    } else {
        printf("login successful! welcome %s.\n", username);
    }

}

void do_quit( void )
{
    puts("Clearing your credentials from memory...");
    for(size_t i = 0; i < 64; i++){
        g_username[i] = 0;
        g_password[i] = 0;
    }
    exit(0);
}

void win( void )
{
    system("cat ./flag.txt");
}