// --- Function: _DT_INIT @ 0040033c ---

void _DT_INIT(void)

{
  if (PTR___gmon_start___00402fe0 != (undefined *)0x0) {
    (*(code *)PTR___gmon_start___00402fe0)();
  }
  return;
}



// --- Function: FUN_00400360 @ 00400360 ---

void FUN_00400360(void)

{
  (*(code *)PTR_00402ff8)();
  return;
}



// --- Function: puts @ 00400370 ---

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int puts(char *__s)

{
  int iVar1;
  
  iVar1 = (*(code *)PTR_puts_00403000)();
  return iVar1;
}



// --- Function: strlen @ 00400380 ---

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

size_t strlen(char *__s)

{
  size_t sVar1;
  
  sVar1 = (*(code *)PTR_strlen_00403008)();
  return sVar1;
}



// --- Function: printf @ 00400390 ---

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int printf(char *__format,...)

{
  int iVar1;
  
  iVar1 = (*(code *)PTR_printf_00403010)();
  return iVar1;
}



// --- Function: __isoc23_scanf @ 004003a0 ---

void __isoc23_scanf(void)

{
  (*(code *)PTR___isoc23_scanf_00403018)();
  return;
}



// --- Function: strcmp @ 004003b0 ---

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int strcmp(char *__s1,char *__s2)

{
  int iVar1;
  
  iVar1 = (*(code *)PTR_strcmp_00403020)();
  return iVar1;
}



// --- Function: entry @ 004003c0 ---

void processEntry entry(undefined8 param_1,undefined8 param_2)

{
  undefined1 auStack_8 [8];
  
  (*(code *)PTR___libc_start_main_00402fd8)
            (FUN_0040053e,param_2,&stack0x00000008,0,0,param_1,auStack_8);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}



// --- Function: FUN_004003f0 @ 004003f0 ---

void FUN_004003f0(void)

{
  return;
}



// --- Function: FUN_00400400 @ 00400400 ---

/* WARNING: Removing unreachable block (ram,0x0040040d) */
/* WARNING: Removing unreachable block (ram,0x00400417) */

void FUN_00400400(void)

{
  return;
}



// --- Function: FUN_00400430 @ 00400430 ---

/* WARNING: Removing unreachable block (ram,0x0040044f) */
/* WARNING: Removing unreachable block (ram,0x00400459) */

void FUN_00400430(void)

{
  return;
}



// --- Function: _FINI_0 @ 00400470 ---

void _FINI_0(void)

{
  if (DAT_0040302c == '\0') {
    FUN_00400400();
    DAT_0040302c = 1;
    return;
  }
  return;
}



// --- Function: _INIT_0 @ 004004a0 ---

void _INIT_0(void)

{
  FUN_00400430();
  return;
}



// --- Function: FUN_004004a6 @ 004004a6 ---

void FUN_004004a6(char *param_1)

{
  size_t sVar1;
  int local_1c;
  
  local_1c = 0;
  while( true ) {
    sVar1 = strlen(param_1);
    if (sVar1 <= (ulong)(long)local_1c) break;
    param_1[local_1c] = param_1[local_1c] + '\x01';
    local_1c = local_1c + 1;
  }
  return;
}



// --- Function: FUN_00400503 @ 00400503 ---

bool FUN_00400503(char *param_1)

{
  int iVar1;
  
  FUN_004004a6(param_1);
  iVar1 = strcmp(param_1,"bcdef");
  return iVar1 == 0;
}



// --- Function: FUN_0040053e @ 0040053e ---

undefined8 FUN_0040053e(void)

{
  int iVar1;
  undefined1 local_48 [64];
  
  puts("--- Secure Vault System v1.0 ---");
  printf("Enter Access Key: ");
  __isoc23_scanf(&DAT_004012bc,local_48);
  iVar1 = FUN_00400503(local_48);
  if (iVar1 == 0) {
    puts("Access Denied! Unauthorized attempt logged.");
  }
  else {
    puts("Access Granted! The secret is: 42");
  }
  return 0;
}



// --- Function: _DT_FINI @ 004005a4 ---

void _DT_FINI(void)

{
  return;
}



// --- Function: __libc_start_main @ 00404000 ---

/* WARNING: Control flow encountered bad instruction data */

void __libc_start_main(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



// --- Function: puts @ 00404008 ---

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int puts(char *__s)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



// --- Function: strlen @ 00404010 ---

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

size_t strlen(char *__s)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



// --- Function: printf @ 00404018 ---

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int printf(char *__format,...)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



// --- Function: __isoc23_scanf @ 00404020 ---

/* WARNING: Control flow encountered bad instruction data */

void __isoc23_scanf(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



// --- Function: strcmp @ 00404028 ---

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int strcmp(char *__s1,char *__s2)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



// --- Function: __gmon_start__ @ 00404030 ---

/* WARNING: Control flow encountered bad instruction data */

void __gmon_start__(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



