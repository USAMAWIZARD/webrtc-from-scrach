#include <glib.h>
#include <json-glib/json-glib.h>
#include <stdbool.h>
#include <stdint.h>
enum random {
  RANDOM_NUMBER_STRING,
  RANDOM_CHAR_STRING,
  RANDOM_BIN,
};

static gchar *get_string_from_json_object(JsonObject *object);
int strcicmp(char const *a, char const *b);
void get_random_string(gchar **data_pointer, uint32_t length, uint8_t type);

guchar *hexstr_to_char(const char *hexstr);
void print_hex(const unsigned char *data, size_t length);
uint32_t hexstr_to_char_2(guchar **p_str, gchar *str);
void print_aes_matrix(uint8_t (*ptr)[4], uint8_t numrow);

void increment_binary_number(unsigned char *number, size_t length); 
