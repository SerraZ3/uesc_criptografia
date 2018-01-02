/*
 *---------------------------------------------------------------------
 *
 *   File    : aes.c
 *   Created : 2018-01-01
 *   Modified: 2018-01-01
 *
 *   Algoritmo de criptografia do AES
 *
 *---------------------------------------------------------------------
 */

/**
 * --------------------------------------------------------------------
 * INCLUDES
 * --------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * --------------------------------------------------------------------
 * MACROS
 * --------------------------------------------------------------------
 */


/**
 * --------------------------------------------------------------------
 * TIPOS
 * --------------------------------------------------------------------
 */



/**
 * --------------------------------------------------------------------
 * VARIÁVEIS GLOBAIS
 * --------------------------------------------------------------------
 */


/**
 * --------------------------------------------------------------------
 * PROTÓTIPOS DE FUNÇÕES
 * --------------------------------------------------------------------
 */



/**
 * --------------------------------------------------------------------
 * FUNÇÃO PRINCIPAL MAIN
 * --------------------------------------------------------------------
 */

int main (int argc, char **argv)
{
    // Verifica a quantidade de argumentos
    if (argc != 4)
        printf("AES 1.0 (01 Janeiro 2018)."
            "\n\nUSO: %s arquivo [-ação] k"
            "\n\nONDE:"
            "\n\tarquivo\t\t:arquivo TEXTO para ser criptografado."
            "\n\t\t\t|arquivo BINÁRIO para ser descriptografado."
            "\n\tk\t\t:chave de dezesseis-caracteres (ASCII)."
            "\n\nPadrão da criptografia/descriptografia é modo de operação Electronic Code Book sem geração de log."
            "\nCaso definido uma opção de log, o log de chaves também será gerado."
            "\n\nAÇÃO:"
            "\n\t-c\t\t:criptografar entrada."
            "\n\t-d\t\t:descriptografar entrada."
            "\n\t-ch\t\t:criptografar entrada com dezeseis digitos hexadecimal [0-F]."
            "\n\t-dh\t\t:descriptografar entrada com dezeseis digitos hexadecimal [0-F]."
            "\n\nOPERAÇÃO:"
            "\n\t-cbc\t\t:defini modo de operação Cipher Block Chaining."
            "\n\nOPÇÕES:"
            "\n\t-logb\t\t:gerar log de operação em binário."
            "\n\t-logh\t\t:gerar log de operação em hexadecimal."
            "\n\nEXEMPLOS:"
            "\n\t%s mensagem.txt -c CHAVEOIT -cbc -logb"
            "\n\t%s mensagem-txt.des -d CHAVEOIT -cbc -logb"
            "\n\t%s mensagem.txt -ch df01ff234abc3d4f -cbc -logh"
            "\n\t%s mensagem-txt.des -dh df01ff234abc3d4f -cbc -logh\n\n", argv[0], argv[0], argv[0], argv[0], argv[0]);
    else
    {
        /**
         * armazenandoChave
         */
        chave_8B.l = 0x0;
        chave_8B.r = 0x0;
        if ((strcmp(argv[2], "-c") == 0) || (strcmp(argv[2], "-d") == 0))
        {
            if (strlen(argv[3]) != 8)
            {
                printf("Chave inválida [%s]. Digite uma chave com 8 caracteres.\n", argv[3]);
                exit(1);
            }
            else
            {
                for (i = 0, j = tam_meio_bloco; i < tam_meio_bloco; i++, j++)
                {
                    chave_8B.l = (chave_8B.l << 8) | argv[3][i];
                    chave_8B.r = (chave_8B.r << 8) | argv[3][j];
                }
            }
        }
        else if ((strcmp(argv[2], "-ch") == 0) || (strcmp(argv[2], "-dh") == 0))
        {
            if (strlen(argv[3]) != 16)
            {
                printf("Chave hexadecimal inválida [%s]. Digite uma chave com 16 caracteres [0-F].\n", argv[3]);
                exit(1);
            }
            else
            {
                for (i = 0, j = tam_meio_bloco_h; i < tam_meio_bloco_h; i++, j++)
                {
                    switch (argv[3][i])
                    {
                        case '0':
                            chave_8B.l = (chave_8B.l << 4) | 0x0;
                            break;

                        case '1':
                            chave_8B.l = (chave_8B.l << 4) | 0x1;
                            break;

                        case '2':
                            chave_8B.l = (chave_8B.l << 4) | 0x2;
                            break;

                        case '3':
                            chave_8B.l = (chave_8B.l << 4) | 0x3;
                            break;

                        case '4':
                            chave_8B.l = (chave_8B.l << 4) | 0x4;
                            break;

                        case '5':
                            chave_8B.l = (chave_8B.l << 4) | 0x5;
                            break;

                        case '6':
                            chave_8B.l = (chave_8B.l << 4) | 0x6;
                            break;

                        case '7':
                            chave_8B.l = (chave_8B.l << 4) | 0x7;
                            break;

                        case '8':
                            chave_8B.l = (chave_8B.l << 4) | 0x8;
                            break;

                        case '9':
                            chave_8B.l = (chave_8B.l << 4) | 0x9;
                            break;

                        case 'a':
                        case 'A':
                            chave_8B.l = (chave_8B.l << 4) | 0xa;
                            break;

                        case 'b':
                        case 'B':
                            chave_8B.l = (chave_8B.l << 4) | 0xb;
                            break;

                        case 'c':
                        case 'C':
                            chave_8B.l = (chave_8B.l << 4) | 0xc;
                            break;

                        case 'd':
                        case 'D':
                            chave_8B.l = (chave_8B.l << 4) | 0xd;
                            break;

                        case 'e':
                        case 'E':
                            chave_8B.l = (chave_8B.l << 4) | 0xe;
                            break;

                        case 'f':
                        case 'F':
                            chave_8B.l = (chave_8B.l << 4) | 0xf;
                            break;

                        default:
                            printf("Chave hexadecimal inválida [%s].\n", argv[3]);
                            exit(1);
                            break;

                    }

                    switch (argv[3][j])
                    {
                        case '0':
                            chave_8B.r = (chave_8B.r << 4) | 0x0;
                            break;

                        case '1':
                            chave_8B.r = (chave_8B.r << 4) | 0x1;
                            break;

                        case '2':
                            chave_8B.r = (chave_8B.r << 4) | 0x2;
                            break;

                        case '3':
                            chave_8B.r = (chave_8B.r << 4) | 0x3;
                            break;

                        case '4':
                            chave_8B.r = (chave_8B.r << 4) | 0x4;
                            break;

                        case '5':
                            chave_8B.r = (chave_8B.r << 4) | 0x5;
                            break;

                        case '6':
                            chave_8B.r = (chave_8B.r << 4) | 0x6;
                            break;

                        case '7':
                            chave_8B.r = (chave_8B.r << 4) | 0x7;
                            break;

                        case '8':
                            chave_8B.r = (chave_8B.r << 4) | 0x8;
                            break;

                        case '9':
                            chave_8B.r = (chave_8B.r << 4) | 0x9;
                            break;

                        case 'a':
                        case 'A':
                            chave_8B.r = (chave_8B.r << 4) | 0xa;
                            break;

                        case 'b':
                        case 'B':
                            chave_8B.r = (chave_8B.r << 4) | 0xb;
                            break;

                        case 'c':
                        case 'C':
                            chave_8B.r = (chave_8B.r << 4) | 0xc;
                            break;

                        case 'd':
                        case 'D':
                            chave_8B.r = (chave_8B.r << 4) | 0xd;
                            break;

                        case 'e':
                        case 'E':
                            chave_8B.r = (chave_8B.r << 4) | 0xe;
                            break;

                        case 'f':
                        case 'F':
                            chave_8B.r = (chave_8B.r << 4) | 0xf;
                            break;

                        default:
                            printf("Chave hexadecimal inválida [%s].\n", argv[3]);
                            exit(1);
                            break;

                    }

                }
            }
        }
        // end-armazenandoChave

        // ------------------------------------------------------------------------------------------

        /**
         * inicializando32CasasBinarias
         */
        bit.b32 = 0x1;
        bit.b31 = 0x2;
        bit.b30 = 0x4;
        bit.b29 = 0x8;
        bit.b28 = 0x10;
        bit.b27 = 0x20;
        bit.b26 = 0x40;
        bit.b25 = 0x80;
        bit.b24 = 0x100;
        bit.b23 = 0x200;
        bit.b22 = 0x400;
        bit.b21 = 0x800;
        bit.b20 = 0x1000;
        bit.b19 = 0x2000;
        bit.b18 = 0x4000;
        bit.b17 = 0x8000;
        bit.b16 = 0x10000;
        bit.b15 = 0x20000;
        bit.b14 = 0x40000;
        bit.b13 = 0x80000;
        bit.b12 = 0x100000;
        bit.b11 = 0x200000;
        bit.b10 = 0x400000;
        bit.b09 = 0x800000;
        bit.b08 = 0x1000000;
        bit.b07 = 0x2000000;
        bit.b06 = 0x4000000;
        bit.b05 = 0x8000000;
        bit.b04 = 0x10000000;
        bit.b03 = 0x20000000;
        bit.b02 = 0x40000000;
        bit.b01 = 0x80000000;
        // end-inicializando32CasasBinarias

        // ------------------------------------------------------------------------------------------

        /**
         * Geração de chaves
         */
        tam_chave = strlen(argv[3]);

        if ((argc == 5 && (strcmp(argv[4], "-logb") == 0 || (strcmp(argv[4], "-logh") == 0)))
            || (argc == 6 && (strcmp(argv[5], "-logb") == 0 || strcmp(argv[5], "-logh") == 0)))
        {
            nome_f_log_ks = malloc(((tam_chave + 12) * sizeof(char)) + 1);

            if (nome_f_log_ks == NULL)
            {
                printf("Erro ao alocar memória p/ arquivo saída log.\n");
                exit(1);
            }

            strcpy(nome_f_log_ks, argv[3]);
            if ((f_log_key = fopen(strcat( nome_f_log_ks, "-keysched.ks"), "w")) == NULL)
            {
                printf("Erro ao criar arquivo de log\n");
                exit(1);
            }

            fprintf(f_log_key, "Chave eh: %s\n", argv[3]);
            fprintf(f_log_key, "Binario: ");
            fImprima4BBin(chave_8B.l, &bit, f_log_key);
            fImprima4BBin(chave_8B.r, &bit, f_log_key);
            fprintf(f_log_key, "\n\n");

            fprintf(f_log_key, "+------");
            fprintf(f_log_key, "+------------------------------");
            fprintf(f_log_key, "+------------------------------");
            fprintf(f_log_key, "+-------------------------------------------------------------");
            fprintf(f_log_key, "+--------------------------------------------------+\n");
            fprintf(f_log_key, "| %4s | %-28s | %-28s | %-59s | %-48s |\n", "i", "Ci", "Di", "Li", "Ki");
            fprintf(f_log_key, "+------");
            fprintf(f_log_key, "+------------------------------");
            fprintf(f_log_key, "+------------------------------");
            fprintf(f_log_key, "+-------------------------------------------------------------");
            fprintf(f_log_key, "+--------------------------------------------------+\n");

            fprintf(f_log_key, "| %4d | ", 1);
            pc1Bloco8B(&chave_8B, &chave_7B, &bit);
            fImprima7BBin(&chave_7B, &bit, f_log_key);

            // Geração de c1
            leftShiftCircular7B(&chave_7B, &bit);
            fImprima7BBin(&chave_7B, &bit, f_log_key);
            pc2Bloco7B(&chave_7B, &chave.c1, &bit);
            fImprima6BBin(&chave.c1, &bit, f_log_key);

            // Geração de c2
            fprintf(f_log_key, "\n| %4d | ", 2);
            fImprima7BBin(&chave_7B, &bit, f_log_key);
            leftShiftCircular7B(&chave_7B, &bit);
            fImprima7BBin(&chave_7B, &bit, f_log_key);
            pc2Bloco7B(&chave_7B, &chave.c2, &bit);
            fImprima6BBin(&chave.c2, &bit, f_log_key);

            // Geração de c3
            fprintf(f_log_key, "\n| %4d | ", 3);
            fImprima7BBin(&chave_7B, &bit, f_log_key);
            leftShiftCircular7B(&chave_7B, &bit);
            leftShiftCircular7B(&chave_7B, &bit);
            fImprima7BBin(&chave_7B, &bit, f_log_key);
            pc2Bloco7B(&chave_7B, &chave.c3, &bit);
            fImprima6BBin(&chave.c3, &bit, f_log_key);

            // Geração de c4
            fprintf(f_log_key, "\n| %4d | ", 4);
            fImprima7BBin(&chave_7B, &bit, f_log_key);
            leftShiftCircular7B(&chave_7B, &bit);
            leftShiftCircular7B(&chave_7B, &bit);
            fImprima7BBin(&chave_7B, &bit, f_log_key);
            pc2Bloco7B(&chave_7B, &chave.c4, &bit);
            fImprima6BBin(&chave.c4, &bit, f_log_key);

            // Geração de c5
            fprintf(f_log_key, "\n| %4d | ", 5);
            fImprima7BBin(&chave_7B, &bit, f_log_key);
            leftShiftCircular7B(&chave_7B, &bit);
            leftShiftCircular7B(&chave_7B, &bit);
            fImprima7BBin(&chave_7B, &bit, f_log_key);
            pc2Bloco7B(&chave_7B, &chave.c5, &bit);
            fImprima6BBin(&chave.c5, &bit, f_log_key);

            // Geração de c6
            fprintf(f_log_key, "\n| %4d | ", 6);
            fImprima7BBin(&chave_7B, &bit, f_log_key);
            leftShiftCircular7B(&chave_7B, &bit);
            leftShiftCircular7B(&chave_7B, &bit);
            fImprima7BBin(&chave_7B, &bit, f_log_key);
            pc2Bloco7B(&chave_7B, &chave.c6, &bit);
            fImprima6BBin(&chave.c6, &bit, f_log_key);

            // Geração de c7
            fprintf(f_log_key, "\n| %4d | ", 7);
            fImprima7BBin(&chave_7B, &bit, f_log_key);
            leftShiftCircular7B(&chave_7B, &bit);
            leftShiftCircular7B(&chave_7B, &bit);
            fImprima7BBin(&chave_7B, &bit, f_log_key);
            pc2Bloco7B(&chave_7B, &chave.c7, &bit);
            fImprima6BBin(&chave.c7, &bit, f_log_key);

            // Geração de c8
            fprintf(f_log_key, "\n| %4d | ", 8);
            fImprima7BBin(&chave_7B, &bit, f_log_key);
            leftShiftCircular7B(&chave_7B, &bit);
            leftShiftCircular7B(&chave_7B, &bit);
            fImprima7BBin(&chave_7B, &bit, f_log_key);
            pc2Bloco7B(&chave_7B, &chave.c8, &bit);
            fImprima6BBin(&chave.c8, &bit, f_log_key);

            // Geração de c9
            fprintf(f_log_key, "\n| %4d | ", 9);
            fImprima7BBin(&chave_7B, &bit, f_log_key);
            leftShiftCircular7B(&chave_7B, &bit);
            fImprima7BBin(&chave_7B, &bit, f_log_key);
            pc2Bloco7B(&chave_7B, &chave.c9, &bit);
            fImprima6BBin(&chave.c9, &bit, f_log_key);

            // Geração de c10
            fprintf(f_log_key, "\n| %4d | ", 10);
            fImprima7BBin(&chave_7B, &bit, f_log_key);
            leftShiftCircular7B(&chave_7B, &bit);
            leftShiftCircular7B(&chave_7B, &bit);
            fImprima7BBin(&chave_7B, &bit, f_log_key);
            pc2Bloco7B(&chave_7B, &chave.c10, &bit);
            fImprima6BBin(&chave.c10, &bit, f_log_key);

            // Geração de c11
            fprintf(f_log_key, "\n| %4d | ", 11);
            fImprima7BBin(&chave_7B, &bit, f_log_key);
            leftShiftCircular7B(&chave_7B, &bit);
            leftShiftCircular7B(&chave_7B, &bit);
            fImprima7BBin(&chave_7B, &bit, f_log_key);
            pc2Bloco7B(&chave_7B, &chave.c11, &bit);
            fImprima6BBin(&chave.c11, &bit, f_log_key);

            // Geração de c12
            fprintf(f_log_key, "\n| %4d | ", 12);
            fImprima7BBin(&chave_7B, &bit, f_log_key);
            leftShiftCircular7B(&chave_7B, &bit);
            leftShiftCircular7B(&chave_7B, &bit);
            fImprima7BBin(&chave_7B, &bit, f_log_key);
            pc2Bloco7B(&chave_7B, &chave.c12, &bit);
            fImprima6BBin(&chave.c12, &bit, f_log_key);

            // Geração de c13
            fprintf(f_log_key, "\n| %4d | ", 13);
            fImprima7BBin(&chave_7B, &bit, f_log_key);
            leftShiftCircular7B(&chave_7B, &bit);
            leftShiftCircular7B(&chave_7B, &bit);
            fImprima7BBin(&chave_7B, &bit, f_log_key);
            pc2Bloco7B(&chave_7B, &chave.c13, &bit);
            fImprima6BBin(&chave.c13, &bit, f_log_key);

            // Geração de c14
            fprintf(f_log_key, "\n| %4d | ", 14);
            fImprima7BBin(&chave_7B, &bit, f_log_key);
            leftShiftCircular7B(&chave_7B, &bit);
            leftShiftCircular7B(&chave_7B, &bit);
            fImprima7BBin(&chave_7B, &bit, f_log_key);
            pc2Bloco7B(&chave_7B, &chave.c14, &bit);
            fImprima6BBin(&chave.c14, &bit, f_log_key);

            // Geração de c15
            fprintf(f_log_key, "\n| %4d | ", 15);
            fImprima7BBin(&chave_7B, &bit, f_log_key);
            leftShiftCircular7B(&chave_7B, &bit);
            leftShiftCircular7B(&chave_7B, &bit);
            fImprima7BBin(&chave_7B, &bit, f_log_key);
            pc2Bloco7B(&chave_7B, &chave.c15, &bit);
            fImprima6BBin(&chave.c15, &bit, f_log_key);

            // Geração de c16
            fprintf(f_log_key, "\n| %4d | ", 16);
            fImprima7BBin(&chave_7B, &bit, f_log_key);
            leftShiftCircular7B(&chave_7B, &bit);
            fImprima7BBin(&chave_7B, &bit, f_log_key);
            pc2Bloco7B(&chave_7B, &chave.c16, &bit);
            fImprima6BBin(&chave.c16, &bit, f_log_key);
            // end-gereChaves

            fprintf(f_log_key, "\n+------");
            fprintf(f_log_key, "+------------------------------");
            fprintf(f_log_key, "+------------------------------");
            fprintf(f_log_key, "+-------------------------------------------------------------");
            fprintf(f_log_key, "+--------------------------------------------------+\n");
            fprintf(f_log_key, "| %4s | %-14s%14s | %-14s%14s | %-29s%30s | %-24s%24s |\n",
                           "-", "b01", "b28", "b29", "b56", "b01", "b56", "b01", "b48");
            fprintf(f_log_key, "+------");
            fprintf(f_log_key, "+------------------------------");
            fprintf(f_log_key, "+------------------------------");
            fprintf(f_log_key, "+-------------------------------------------------------------");
            fprintf(f_log_key, "+--------------------------------------------------+\n\n");

            // Fecha fluxo com arquivos
            free(nome_f_log_ks);
            fclose(f_log_key);
            
        }
        else
        {

            pc1Bloco8B(&chave_8B, &chave_7B, &bit);

            // Geração de c1
            leftShiftCircular7B(&chave_7B, &bit);
            pc2Bloco7B(&chave_7B, &chave.c1, &bit);

            // Geração de c2
            leftShiftCircular7B(&chave_7B, &bit);
            pc2Bloco7B(&chave_7B, &chave.c2, &bit);

            // Geração de c3
            leftShiftCircular7B(&chave_7B, &bit);
            leftShiftCircular7B(&chave_7B, &bit);
            pc2Bloco7B(&chave_7B, &chave.c3, &bit);

            // Geração de c4
            leftShiftCircular7B(&chave_7B, &bit);
            leftShiftCircular7B(&chave_7B, &bit);
            pc2Bloco7B(&chave_7B, &chave.c4, &bit);

            // Geração de c5
            leftShiftCircular7B(&chave_7B, &bit);
            leftShiftCircular7B(&chave_7B, &bit);
            pc2Bloco7B(&chave_7B, &chave.c5, &bit);

            // Geração de c6
            leftShiftCircular7B(&chave_7B, &bit);
            leftShiftCircular7B(&chave_7B, &bit);
            pc2Bloco7B(&chave_7B, &chave.c6, &bit);

            // Geração de c7
            leftShiftCircular7B(&chave_7B, &bit);
            leftShiftCircular7B(&chave_7B, &bit);
            pc2Bloco7B(&chave_7B, &chave.c7, &bit);

            // Geração de c8
            leftShiftCircular7B(&chave_7B, &bit);
            leftShiftCircular7B(&chave_7B, &bit);
            pc2Bloco7B(&chave_7B, &chave.c8, &bit);

            // Geração de c9
            leftShiftCircular7B(&chave_7B, &bit);
            pc2Bloco7B(&chave_7B, &chave.c9, &bit);

            // Geração de c10
            leftShiftCircular7B(&chave_7B, &bit);
            leftShiftCircular7B(&chave_7B, &bit);
            pc2Bloco7B(&chave_7B, &chave.c10, &bit);

            // Geração de c11
            leftShiftCircular7B(&chave_7B, &bit);
            leftShiftCircular7B(&chave_7B, &bit);
            pc2Bloco7B(&chave_7B, &chave.c11, &bit);

            // Geração de c12
            leftShiftCircular7B(&chave_7B, &bit);
            leftShiftCircular7B(&chave_7B, &bit);
            pc2Bloco7B(&chave_7B, &chave.c12, &bit);

            // Geração de c13
            leftShiftCircular7B(&chave_7B, &bit);
            leftShiftCircular7B(&chave_7B, &bit);
            pc2Bloco7B(&chave_7B, &chave.c13, &bit);

            // Geração de c14
            leftShiftCircular7B(&chave_7B, &bit);
            leftShiftCircular7B(&chave_7B, &bit);
            pc2Bloco7B(&chave_7B, &chave.c14, &bit);

            // Geração de c15
            leftShiftCircular7B(&chave_7B, &bit);
            leftShiftCircular7B(&chave_7B, &bit);
            pc2Bloco7B(&chave_7B, &chave.c15, &bit);

            // Geração de c16
            leftShiftCircular7B(&chave_7B, &bit);
            pc2Bloco7B(&chave_7B, &chave.c16, &bit);

        }
        /*
         * end-gereChaves
         */

        // ------------------------------------------------------------------------------------------

        // Armazenando nome do arquivo de saida
        tam_nome_f_in = strlen(argv[1]);
        nome_f_des = malloc(tam_nome_f_in + tam_chave + 6);
        
        if (nome_f_des == NULL)
        {
            printf("Erro ao alocar memória p/ arquivo saída DES.\n");
            exit(1);
        }
        
        strcpy(nome_f_des, argv[3]);
        strcat(nome_f_des, "-");

        nome_f_in = malloc(tam_nome_f_in + 1);
        
        if (nome_f_in == NULL)
        {
            printf("Erro ao alocar memória p/ nome do arquivo de entrada.\n");
            exit(1);
        }
        
        strcpy(nome_f_in, argv[1]);

        for (j = 0, i = tam_chave + 1; j < tam_nome_f_in; j++, i++)
        {
        	if (argv[1][j] == '.')
                nome_f_des[i] = '-';
            else
        		nome_f_des[i] = argv[1][j];
        }
        nome_f_des[i] = '\0';
        // end-armazenando nome do arquivo de saida

        // Verifica a operação para cifrar
        if ((strcmp(argv[2], "-c") == 0) || (strcmp(argv[2], "-ch") == 0))
		{
	        // abreFluxoComArquivos
			if ((f_in = fopen(nome_f_in, "r")) == NULL)
	        {
	            printf("O arquivo [%s] nao existe.\n", argv[1]);
	            exit(1);
	        }
	        
	        if ((f_out = fopen(strcat( nome_f_des, ".des" ), "wb")) == NULL)
	        {
	            printf("Erro ao criar arquivo cifrado\n");
	            exit(1);
	        }
	        // end-abreFluxoComArquivos

            // Mensagem p/ loading
            printf("Em execução, aguarde...\n");

            // Aplica cifra modo de operação
            if (argc == 6)
            {
                if (strcmp(argv[4], "-cbc") == 0)
                {
                    if (strcmp(argv[5], "-logb") == 0)
                        cifreCBCLogb(&bit, f_in, f_out, &chave, argv[3]);
                    else if (strcmp(argv[5], "-logh") == 0)
                        cifreCBCLogh(&bit, f_in, f_out, &chave, argv[3]);
                    else
                    {
                        cifreCBC(&bit, f_in, f_out, &chave);
                        printf("Opção desconhecida [%s]. Efetuado opção padrão s/Log.\n", argv[5]);
                    }
                }
                else
                {
                    if (strcmp(argv[5], "-logb") == 0)
                        cifreECBLogb(&bit, f_in, f_out, &chave, argv[3]);
                    else if (strcmp(argv[5], "-logh") == 0)
                        cifreECBLogh(&bit, f_in, f_out, &chave, argv[3]);
                    else
                        cifreECB(&bit, f_in, f_out, &chave);
                    printf("Operação desconhecida [%s]. Efetuado operaçao padrão ECB.\n", argv[4]);
                }
            }
            else if (argc == 5)
            {
                if (strcmp(argv[4], "-cbc") == 0)
                    cifreCBC(&bit, f_in, f_out, &chave);
                else if (strcmp(argv[4], "-logb") == 0)
                    cifreECBLogb(&bit, f_in, f_out, &chave, argv[3]);
                else if (strcmp(argv[4], "-logh") == 0)
                    cifreECBLogh(&bit, f_in, f_out, &chave, argv[3]);
                else
                {
                    cifreECB(&bit, f_in, f_out, &chave);
                    printf("Operação desconhecida [%s]. Efetuado operaçao padrão ECB.\n", argv[4]);
                }
            }
            else
                cifreECB(&bit, f_in, f_out, &chave);
           	
            // Fecha fluxo com arquivos
            fclose(f_in);
            fclose(f_out);

            printf("Criptografia finalizada.\n");
            
		}
        // Verifica a operação para decifrar
		else if (strcmp(argv[2], "-d") == 0 || strcmp(argv[2], "-dh") == 0)
        {
        	// abreFluxoComArquivos
			if ((f_in = fopen(nome_f_in, "rb")) == NULL)
	        {
	            printf("O arquivo [%s] nao existe\n", argv[1]);
	            exit(1);
	        }
	        
	        if ((f_out = fopen(strcat( nome_f_des, ".txt" ), "w")) == NULL)
	        {
	            printf("Erro ao criar arquivo decifrado\n");
	            exit(1);
	        }
	        // end-abreFluxoComArquivos

            // Mensagem p/ loading
            printf("Em execução, aguarde...\n");

            // Aplica decifra modo de operação
            if (argc == 6)
            {
                if (strcmp(argv[4], "-cbc") == 0)
                {
                    if (strcmp(argv[5], "-logb") == 0)
                        decifreCBCLogb(&bit, f_in, f_out, &chave, argv[3]);
                    else if (strcmp(argv[5], "-logh") == 0)
                        decifreCBCLogh(&bit, f_in, f_out, &chave, argv[3]);
                    else
                    {
                        decifreCBC(&bit, f_in, f_out, &chave);
                        printf("Opção desconhecida [%s]. Efetuado opção padrão s/Log.\n", argv[5]);
                    }
                }
                else
                {
                    if (strcmp(argv[5], "-logb") == 0)
                        decifreECBLogb(&bit, f_in, f_out, &chave, argv[3]);
                    else if (strcmp(argv[5], "-logh") == 0)
                        decifreECBLogh(&bit, f_in, f_out, &chave, argv[3]);
                    else
                        decifreECB(&bit, f_in, f_out, &chave);
                    printf("Operação desconhecida [%s]. Efetuado operaçao padrão ECB.\n", argv[4]);
                }
            }
            else if (argc == 5)
            {
                if (strcmp(argv[4], "-cbc") == 0)
                    decifreCBC(&bit, f_in, f_out, &chave);
                else if (strcmp(argv[4], "-logb") == 0)
                    decifreECBLogb(&bit, f_in, f_out, &chave, argv[3]);
                else if (strcmp(argv[4], "-logh") == 0)
                    decifreECBLogh(&bit, f_in, f_out, &chave, argv[3]);
                else
                {
                    decifreECB(&bit, f_in, f_out, &chave);
                    printf("Operação desconhecida [%s]. Efetuado operaçao padrão ECB.\n", argv[4]);
                }
            }
            else
                decifreECB(&bit, f_in, f_out, &chave);

            // Fecha fluxo com arquivos
            fclose(f_in);
            fclose(f_out);

            printf("Descriptografia finalizada.\n");

        }
		else
            printf("DesP 1.0 (30 Novembro 2017)."
                "\n\nUSO: %s arquivo -ação k [-operação] [-opção]"
                "\n\nONDE:"
                "\n\tarquivo\t\t:arquivo TEXTO para ser criptografado."
                "\n\t\t\t|arquivo BINÁRIO para ser descriptografado."
                "\n\tk\t\t:chave de oito-caracteres (ASCII) ou dezeseis-caracteres (HEX)."
                "\n\nPadrão da criptografia/descriptografia é modo de operação Electronic Code Book sem geração de log."
                "\nCaso definido uma opção de log, o log de chaves também será gerado."
                "\n\nAÇÃO:"
                "\n\t-c\t\t:criptografar entrada."
                "\n\t-d\t\t:descriptografar entrada."
                "\n\t-ch\t\t:criptografar entrada com dezeseis digitos hexadecimal [0-F]."
                "\n\t-dh\t\t:descriptografar entrada com dezeseis digitos hexadecimal [0-F]."
                "\n\nOPERAÇÃO:"
                "\n\t-cbc\t\t:defini modo de operação Cipher Block Chaining."
                "\n\nOPÇÕES:"
                "\n\t-logb\t\t:gerar log de operação em binário."
                "\n\t-logh\t\t:gerar log de operação em hexadecimal."
                "\n\nEXEMPLOS:"
                "\n\t%s mensagem.txt -c CHAVEOIT -cbc -logb"
                "\n\t%s mensagem-txt.des -d CHAVEOIT -cbc -logb"
                "\n\t%s mensagem.txt -ch df01ff234abc3d4f -cbc -logh"
                "\n\t%s mensagem-txt.des -dh df01ff234abc3d4f -cbc -logh\n\n", argv[0], argv[0], argv[0], argv[0], argv[0]);

        free(nome_f_des);
        free(nome_f_in);
    }

	return 0;

} // end-main