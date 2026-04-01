// --- Function: _init @ 0040033c ---

int _init(EVP_PKEY_CTX *ctx)

{
  int iVar1;
  
  iVar1 = 0;
  if (PTR___gmon_start___00402fe0 != (undefined *)0x0) {
    iVar1 = (*(code *)PTR___gmon_start___00402fe0)();
  }
  return iVar1;
}



// --- Function: FUN_00400360 @ 00400360 ---

void FUN_00400360(void)

{
  (*(code *)PTR_00402ff8)();
  return;
}



// --- Function: strncpy @ 00400370 ---

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

char * strncpy(char *__dest,char *__src,size_t __n)

{
  char *pcVar1;
  
  pcVar1 = (char *)(*(code *)PTR_strncpy_00403000)();
  return pcVar1;
}



// --- Function: puts @ 00400380 ---

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int puts(char *__s)

{
  int iVar1;
  
  iVar1 = (*(code *)PTR_puts_00403008)();
  return iVar1;
}



// --- Function: strlen @ 00400390 ---

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

size_t strlen(char *__s)

{
  size_t sVar1;
  
  sVar1 = (*(code *)PTR_strlen_00403010)();
  return sVar1;
}



// --- Function: printf @ 004003a0 ---

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int printf(char *__format,...)

{
  int iVar1;
  
  iVar1 = (*(code *)PTR_printf_00403018)();
  return iVar1;
}



// --- Function: snprintf @ 004003b0 ---

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int snprintf(char *__s,size_t __maxlen,char *__format,...)

{
  int iVar1;
  
  iVar1 = (*(code *)PTR_snprintf_00403020)();
  return iVar1;
}



// --- Function: _start @ 004003c0 ---

void processEntry _start(undefined8 param_1,undefined8 param_2)

{
  undefined1 auStack_8 [8];
  
  (*(code *)PTR___libc_start_main_00402fd8)(main,param_2,&stack0x00000008,0,0,param_1,auStack_8);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}



// --- Function: _dl_relocate_static_pie @ 004003f0 ---

void _dl_relocate_static_pie(void)

{
  return;
}



// --- Function: deregister_tm_clones @ 00400400 ---

/* WARNING: Removing unreachable block (ram,0x0040040d) */
/* WARNING: Removing unreachable block (ram,0x00400417) */

void deregister_tm_clones(void)

{
  return;
}



// --- Function: register_tm_clones @ 00400430 ---

/* WARNING: Removing unreachable block (ram,0x0040044f) */
/* WARNING: Removing unreachable block (ram,0x00400459) */

void register_tm_clones(void)

{
  return;
}



// --- Function: __do_global_dtors_aux @ 00400470 ---

void __do_global_dtors_aux(void)

{
  if (completed_0 == '\0') {
    deregister_tm_clones();
    completed_0 = 1;
    return;
  }
  return;
}



// --- Function: frame_dummy @ 004004a0 ---

void frame_dummy(void)

{
  register_tm_clones();
  return;
}



// --- Function: calculate_checksum @ 004004a6 ---

int calculate_checksum(char *input,int length)

{
  int length_local;
  char *input_local;
  int index;
  int checksum;
  
  checksum = 0;
  for (index = 0; index < length; index = index + 1) {
    checksum = (checksum ^ input[index]) >> 5 | (checksum ^ input[index]) * 8;
  }
  return checksum;
}



// --- Function: validate_password @ 004004fd ---

int validate_password(char *password)

{
  int iVar1;
  size_t sVar2;
  char *password_local;
  int is_valid;
  int result;
  int expected;
  
  sVar2 = strlen(password);
  iVar1 = calculate_checksum(password,(int)sVar2);
  return (uint)(iVar1 == -0x21524111);
}



// --- Function: greet_player @ 00400543 ---

void greet_player(Player *player)

{
  size_t sVar1;
  Player *player_local;
  char buffer [128];
  int msg_len;
  
  snprintf(buffer,0x80,"Hello, %s! Score: %.2f",(double)player->score,player->name);
  sVar1 = strlen(buffer);
  printf("%s (len=%d)\n",buffer,sVar1 & 0xffffffff);
  return;
}



// --- Function: main @ 004005d4 ---

int main(int argc,char **argv)

{
  uint uVar1;
  int iVar2;
  char **argv_local;
  int argc_local;
  Player p;
  int success;
  
  if (argc < 2) {
    printf("Usage: %s <password>\n",*argv);
    uVar1 = 1;
  }
  else {
    p.id = 1;
    strncpy(p.name,"TestUser",0x40);
    p.score = DAT_004012bc;
    iVar2 = validate_password(argv[1]);
    if (iVar2 == 0) {
      puts("Access denied.");
    }
    else {
      p.score = DAT_004012c0;
      greet_player(&p);
      puts("Access granted!");
    }
    uVar1 = (uint)(iVar2 == 0);
  }
  return uVar1;
}



// --- Function: _fini @ 00400698 ---

void _fini(void)

{
  return;
}



// --- Function: __libc_start_main @ 00404000 ---

/* WARNING: Control flow encountered bad instruction data */

void __libc_start_main(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* __libc_start_main@GLIBC_2.34 */
  halt_baddata();
}



// --- Function: strncpy @ 00404008 ---

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

char * strncpy(char *__dest,char *__src,size_t __n)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* strncpy@GLIBC_2.2.5 */
  halt_baddata();
}



// --- Function: puts @ 00404010 ---

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int puts(char *__s)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* puts@GLIBC_2.2.5 */
  halt_baddata();
}



// --- Function: strlen @ 00404018 ---

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

size_t strlen(char *__s)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* strlen@GLIBC_2.2.5 */
  halt_baddata();
}



// --- Function: printf @ 00404020 ---

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int printf(char *__format,...)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* printf@GLIBC_2.2.5 */
  halt_baddata();
}



// --- Function: snprintf @ 00404028 ---

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int snprintf(char *__s,size_t __maxlen,char *__format,...)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* snprintf@GLIBC_2.2.5 */
  halt_baddata();
}



// --- Function: __gmon_start__ @ 00404030 ---

/* WARNING: Control flow encountered bad instruction data */

void __gmon_start__(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



