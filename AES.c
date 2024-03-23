#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

// Tamanho dos vetores onde os dados sao armazenados.
#define MAXCHAR 10000

// Funcao auxiliar para apresentar mensagens de erro.
void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

// Funcao responsavel pela criptografia de plaintext[] de tamanho plaintext_len com a chave key[] e o vetor de inicializacao iv[]. A saida eh armazenada em ciphertext[] e o seu tamanho eh retornado pela funcao.
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;

  /* Criacao e inicializacao do contexto da cifra */
  if(!(ctx = EVP_CIPHER_CTX_new()))
      handleErrors();

  /*
   * Inicializacao da operacao de criptografia.
   * IMPORTANTE - garanta que a chave e IV sejam
   * de tamanhos apropriados para a sua cifra.
   */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
      handleErrors();

  /*
   * Fornece a mensagem a ser criptografada e
   * obtem como saida o texto cifrado.
   * EVP_EncryptUpdate pode ser chamado multiplas
   * vezes se necessario.
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
      handleErrors();
  ciphertext_len = len;

  /*
   * Finaliza o processo de criptografia.
   * Mais bytes podem ser inseridos na saida se for
   * necessario, por isso o tamanho deve ser atualizado.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
      handleErrors();
  ciphertext_len += len;

  /* Liberacao de recursos */
  EVP_CIPHER_CTX_free(ctx);
  return ciphertext_len;
}

// Funcao responsavel pela decriptografia de ciphertext[] de tamanho ciphertext_len com a chave key[] e o vetor de inicializacao iv[]. A saida eh armazenada em plaintext[] e o seu tamanho eh retornado pela funcao.
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;

  /* Criacao e inicializacao do contexto da cifra */
  if(!(ctx = EVP_CIPHER_CTX_new()))
      handleErrors();

  /*
   * Inicializacao da operacao de decriptografia.
   * IMPORTANTE - garanta que a chave e IV sejam
   * de tamanhos apropriados para a sua cifra.
   */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
      handleErrors();

  /*
   * Fornece a mensagem a ser decriptografada e
   * obtem como saida o texto claro.
   * EVP_DecryptUpdate pode ser chamado multiplas
   * vezes se necessario.
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
      handleErrors();
  plaintext_len = len;

  /*
   * Finaliza o processo de decriptografia.
   * Mais bytes podem ser inseridos na saida se for
   * necessario, por isso o tamanho deve ser atualizado.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
      handleErrors();
  plaintext_len += len;

  /* Liberacao de recursos */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

int main () {
  /*
  * Definicao da chave e do vetor de inicializacao.
  * Em aplicacoes reais, eles nunca devem ser definidos
  * no codigo.
  */
  // Chave de 128 bits
  unsigned char *key = (unsigned char *)"12341234123412341234123412341234";
  // Vetor de inicializacao de 128 bits
  unsigned char *iv = (unsigned char *)"0123456789012345";
  // Mensagem a ser criptografada
  unsigned char *plaintext = (unsigned char *)"AES no modo counter!";

  /*
  * Buffer para o texto cifrado. Garanta que ele seja grande
  * o suficiente para armazenar o texto cifrado, que pode ser maior
  * do que o texto claro de acordo com o algoritmo de criptografia
  * e o modo de operacao escolhidos.
  */
  unsigned char ciphertext[MAXCHAR];
  // Buffer para o texto decriptografado
  unsigned char decryptedtext[MAXCHAR];
  int decryptedtext_len, ciphertext_len;

  // Estruturas para calcular o tempo em microssegundos
  struct timespec start_crypto, end_crypto;
  struct timespec start_decrypto, end_decrypto;
  uint64_t delta_us_crypto;
  uint64_t delta_us_decrypto;

  // Medicao de tempo do inicio da criptografia
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start_crypto);
  // Criptografia do texto claro
  //ciphertext_len = encrypt(plaintext, strlen ((char *)plaintext), key, iv, ciphertext);
  // Medicao de tempo do fim da criptografia
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end_crypto);

  FILE *bin = fopen("./1111.bin","rb");
  ciphertext_len = fread(ciphertext,1,MAXCHAR,bin);
  fclose(bin);
  
  // Apresentacao do texto cifrado como texto ASCII
  printf("Ciphertext is:\n");
  printf("%s\n", ciphertext);

  /*
   * Forma mais indicada de impressao do texto cifrado
   * em hexadecimal e em ASCII
  */
  BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

  // Medicao de tempo do inicio da decriptografia
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start_decrypto);
  // Decriptografia do texto cifrado
  decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);

  // Adicao de um byte NULL ao fim do vetor para indicar o fim quando for imprimir como texto ASCII
  decryptedtext[decryptedtext_len] = '\0';
  // Medicao de tempo do fim da decriptografia
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end_decrypto);

  // Apresentacao do texto decriptografado como texto ASCII
  printf("\nDecrypted text is:\n");
  printf("%s\n", decryptedtext);

  // Calculo do tempo levado para a criptografia e decriptografia em microssegundos
  delta_us_crypto = (end_crypto.tv_sec - start_crypto.tv_sec) * 1000000 + (end_crypto.tv_nsec - start_crypto.tv_nsec) / 1000;
  delta_us_decrypto = (end_decrypto.tv_sec - start_decrypto.tv_sec) * 1000000 + (end_decrypto.tv_nsec - start_decrypto.tv_nsec) / 1000;

  // Apresentacao do tempo total de criptografia e decriptografia
  printf("\nTotal time = %ld us (10^-6 seconds)\n", delta_us_crypto+delta_us_decrypto);

  return 0;
}
