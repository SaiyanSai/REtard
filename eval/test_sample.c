#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// A simple crackme-style program for testing the eval framework

typedef struct {
    int id;
    char name[64];
    float score;
} Player;

int calculate_checksum(const char *input, int length) {
    int checksum = 0;
    int index = 0;
    while (index < length) {
        checksum ^= input[index];
        checksum = (checksum << 3) | (checksum >> 5);
        index++;
    }
    return checksum;
}

int validate_password(const char *password) {
    int expected = 0xDEADBEEF;
    int result = calculate_checksum(password, strlen(password));
    int is_valid = (result == expected);
    return is_valid;
}

void greet_player(Player *player) {
    char buffer[128];
    int msg_len = 0;
    snprintf(buffer, sizeof(buffer), "Hello, %s! Score: %.2f", player->name, player->score);
    msg_len = strlen(buffer);
    printf("%s (len=%d)\n", buffer, msg_len);
}

int main(int argc, char *argv[]) {
    Player p;
    int success = 0;

    if (argc < 2) {
        printf("Usage: %s <password>\n", argv[0]);
        return 1;
    }

    p.id = 1;
    strncpy(p.name, "TestUser", sizeof(p.name));
    p.score = 100.0f;

    success = validate_password(argv[1]);
    if (success) {
        p.score = 9999.0f;
        greet_player(&p);
        printf("Access granted!\n");
    } else {
        printf("Access denied.\n");
    }
    return success ? 0 : 1;
}
