// --- Function: __mingw_invalidParameterHandler @ 00401000 ---

/* WARNING: Unknown calling convention */

void __mingw_invalidParameterHandler
               (wchar_t *expression,wchar_t *function,wchar_t *file,uint line,uintptr_t pReserved)

{
  return;
}



// --- Function: pre_c_init @ 00401010 ---

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int pre_c_init(void)

{
  short sVar1;
  int *piVar2;
  
                    /* Unresolved local var: PIMAGE_DOS_HEADER pDOSHeader@[???]
                       Unresolved local var: PIMAGE_NT_HEADERS pPEHeader@[???]
                       Unresolved local var: PIMAGE_OPTIONAL_HEADER32 pNTHeader32@[???]
                       Unresolved local var: PIMAGE_OPTIONAL_HEADER64 pNTHeader64@[???] */
  managedapp = 0;
  __mingw_initltsdrot_force = 1;
  __mingw_initltsdyn_force = 1;
  __mingw_initltssuo_force = 1;
  if ((IMAGE_DOS_HEADER_00400000.e_magic == (char  [2])0x5a4d) &&
     (*(int *)(IMAGE_DOS_HEADER_00400000.e_lfanew + 0x400000) == 0x4550)) {
    sVar1 = *(short *)((int)IMAGE_DOS_HEADER_00400000.e_res_4_ +
                      (IMAGE_DOS_HEADER_00400000.e_lfanew - 4));
    if (sVar1 == 0x10b) {
      if (0xe < *(uint *)(IMAGE_DOS_HEADER_00400000.e_program +
                         IMAGE_DOS_HEADER_00400000.e_lfanew + 0x34)) {
        managedapp = (int)(*(int *)((int)(IMAGE_NT_HEADERS32_00400080.OptionalHeader.DataDirectory +
                                         -2) + IMAGE_DOS_HEADER_00400000.e_lfanew) != 0);
      }
    }
    else if ((sVar1 == 0x20b) &&
            (0xe < *(uint *)(IMAGE_NT_HEADERS32_00400080.Signature +
                            IMAGE_DOS_HEADER_00400000.e_lfanew + 4))) {
      managedapp = (int)(*(int *)((int)&IMAGE_NT_HEADERS32_00400080.OptionalHeader.DataDirectory[0].
                                        VirtualAddress + IMAGE_DOS_HEADER_00400000.e_lfanew) != 0);
    }
  }
  if (__mingw_app_type == 0) {
    ___set_app_type(1);
  }
  else {
    ___set_app_type(2);
  }
  piVar2 = (int *)___p__fmode();
  *piVar2 = _fmode;
  piVar2 = (int *)___p__commode();
  *piVar2 = _commode;
  _setargv();
  if (_MINGW_INSTALL_DEBUG_MATHERR != 1) {
    return 0;
  }
  __mingw_setusermatherr(_matherr);
  return 0;
}



// --- Function: pre_cpp_init @ 00401120 ---

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void pre_cpp_init(void)

{
  startinfo.newmode = _newmode;
  ___getmainargs(&argc,&argv,&envp,_dowildcard,(_startupinfo *)&startinfo);
  return;
}



// --- Function: __tmainCRTStartup @ 00401160 ---

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int __tmainCRTStartup(void)

{
  char *pcVar1;
  char cVar2;
  void *pvVar3;
  void *pvVar4;
  void *pvVar5;
  undefined4 *puVar6;
  char **ppcVar7;
  int iVar8;
  char *pcVar9;
  bool bVar10;
  int iVar11;
  char **ppcVar12;
  char **ppcVar13;
  char **ppcVar14;
  char **ppcVar15;
  LPSTARTUPINFOA p_Var16;
  int unaff_FS_OFFSET;
  undefined1 local_64 [4];
  STARTUPINFO StartupInfo;
  
                    /* Unresolved local var: _TCHAR * lpszCommandLine@[???]
                       Unresolved local var: WINBOOL inDoubleQuote@[???] */
  p_Var16 = (LPSTARTUPINFOA)local_64;
  for (iVar11 = 0x11; iVar11 != 0; iVar11 = iVar11 + -1) {
    p_Var16->cb = 0;
    p_Var16 = (LPSTARTUPINFOA)&p_Var16->lpReserved;
  }
  if (__mingw_app_type != 0) {
    GetStartupInfoA((LPSTARTUPINFOA)local_64);
  }
                    /* Unresolved local var: void * lock_free@[???]
                       Unresolved local var: void * fiberid@[???]
                       Unresolved local var: int nested@[???]
                       Unresolved local var: ulong ret@[???] */
  pvVar3 = *(void **)(*(int *)(unaff_FS_OFFSET + 0x18) + 4);
  while( true ) {
    pvVar5 = (void *)0x0;
    LOCK();
    pvVar4 = pvVar3;
    if (__native_startup_lock != (void *)0x0) {
      pvVar5 = __native_startup_lock;
      pvVar4 = __native_startup_lock;
    }
    __native_startup_lock = pvVar4;
    UNLOCK();
    if (pvVar5 == (void *)0x0) {
      bVar10 = false;
      goto joined_r0x004013dd;
    }
    if (pvVar3 == pvVar5) break;
    Sleep(1000);
  }
  bVar10 = true;
joined_r0x004013dd:
  if (__native_startup_state == __initializing) {
    __amsg_exit(0x1f);
  }
  else if (__native_startup_state == __uninitialized) {
    __native_startup_state = __initializing;
    __initterm(__xi_a,__xi_z);
  }
  else {
    has_cctor = 1;
  }
  if (__native_startup_state == __initializing) {
    __initterm(__xc_a,__xc_z);
    __native_startup_state = __initialized;
  }
  if (!bVar10) {
    LOCK();
    UNLOCK();
    __native_startup_lock = (void *)0x0;
  }
  if (__dyn_tls_init_callback != (PIMAGE_TLS_CALLBACK)0x0) {
    (*__dyn_tls_init_callback)((PVOID)0x0,2,(PVOID)0x0);
  }
  _pei386_runtime_relocator();
  __mingw_oldexcpt_handler =
       (LPTOP_LEVEL_EXCEPTION_FILTER)SetUnhandledExceptionFilter(_gnu_exception_handler);
  mingw_set_invalid_parameter_handler(__mingw_invalidParameterHandler);
  _fpreset();
  __mingw_winmain_hInstance = (HINSTANCE)&IMAGE_DOS_HEADER_00400000;
  puVar6 = (undefined4 *)___p__acmdln();
  iVar11 = argc;
  bVar10 = false;
  pcVar9 = (char *)*puVar6;
  if (pcVar9 != (char *)0x0) {
    do {
      cVar2 = *pcVar9;
      if (cVar2 < '!') {
        __mingw_winmain_lpCmdLine = pcVar9;
        if (cVar2 == '\0') break;
        if (!bVar10) goto LAB_004012a0;
        bVar10 = true;
      }
      else if (cVar2 == '\"') {
        bVar10 = (bool)(bVar10 ^ 1);
      }
      pcVar9 = pcVar9 + 1;
    } while( true );
  }
  goto LAB_004012bd;
LAB_004012a0:
  if (cVar2 != '\0') {
    do {
      pcVar1 = pcVar9 + 1;
      pcVar9 = pcVar9 + 1;
      __mingw_winmain_lpCmdLine = pcVar9;
      if (*pcVar1 == '\0') break;
    } while (*pcVar1 < '!');
  }
LAB_004012bd:
  if ((__mingw_app_type != 0) &&
     (__mingw_winmain_nShowCmd = 10, ((byte)StartupInfo.dwFillAttribute & 1) != 0)) {
    __mingw_winmain_nShowCmd = (DWORD)(ushort)StartupInfo.dwFlags;
  }
                    /* Unresolved local var: char * * avl@[???]
                       Unresolved local var: int i@[???]
                       Unresolved local var: char * * n@[???] */
  ppcVar7 = (char **)malloc(argc * 4 + 4);
  ppcVar12 = ppcVar7;
  if (0 < iVar11) {
    ppcVar12 = argv + iVar11;
    ppcVar13 = argv;
    ppcVar15 = ppcVar7;
    do {
                    /* Unresolved local var: size_t l@[???] */
      ppcVar14 = ppcVar13 + 1;
      iVar8 = strlen(*ppcVar13);
      pcVar9 = (char *)malloc(iVar8 + 1U);
      *ppcVar15 = pcVar9;
      memcpy(pcVar9,*ppcVar13,iVar8 + 1U);
      ppcVar13 = ppcVar14;
      ppcVar15 = ppcVar15 + 1;
    } while (ppcVar12 != ppcVar14);
    ppcVar12 = ppcVar7 + iVar11;
  }
  *ppcVar12 = (char *)0x0;
  argv = ppcVar7;
  __main();
  ppcVar12 = envp;
  *(char ***)__initenv_exref = envp;
  mainret = _main(argc,argv,ppcVar12);
  if (managedapp != 0) {
    if (has_cctor != 0) {
      return mainret;
    }
    __cexit();
    return mainret;
  }
                    /* WARNING: Subroutine does not return */
  exit(mainret);
}



// --- Function: WinMainCRTStartup @ 004014a0 ---

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int WinMainCRTStartup(void)

{
  int iVar1;
  
                    /* Unresolved local var: int ret@[???] */
  __mingw_app_type = 1;
  iVar1 = __tmainCRTStartup();
  return iVar1;
}



// --- Function: mainCRTStartup @ 004014b0 ---

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int mainCRTStartup(void)

{
  int iVar1;
  
                    /* Unresolved local var: int ret@[???] */
  __mingw_app_type = 0;
  iVar1 = __tmainCRTStartup();
  return iVar1;
}



// --- Function: atexit @ 004014c0 ---

/* WARNING: Unknown calling convention */

int atexit(_PVFV func)

{
  _onexit_t p_Var1;
  
  p_Var1 = __onexit((_onexit_t)func);
  return -(uint)(p_Var1 == (_onexit_t)0x0);
}



// --- Function: ___gcc_register_frame @ 004014e0 ---

void ___gcc_register_frame(void)

{
  HMODULE hModule;
  FARPROC pFVar1;
  
  hModule = GetModuleHandleA("libgcc_s_dw2-1.dll");
  if (hModule == (HMODULE)0x0) {
    _deregister_frame_fn = (FARPROC)0x0;
    pFVar1 = (FARPROC)0x0;
  }
  else {
    _hmod_libgcc = LoadLibraryA("libgcc_s_dw2-1.dll");
    pFVar1 = GetProcAddress(hModule,"__register_frame_info");
    _deregister_frame_fn = GetProcAddress(hModule,"__deregister_frame_info");
  }
  if (pFVar1 != (FARPROC)0x0) {
    (*pFVar1)(&___EH_FRAME_BEGIN__,&_obj);
  }
  atexit(___gcc_deregister_frame);
  return;
}



// --- Function: ___gcc_deregister_frame @ 00401580 ---

void ___gcc_deregister_frame(void)

{
  if (_deregister_frame_fn != (code *)0x0) {
    (*_deregister_frame_fn)(&___EH_FRAME_BEGIN__);
  }
  if (_hmod_libgcc != (HMODULE)0x0) {
    FreeLibrary(_hmod_libgcc);
  }
  return;
}



// --- Function: _printf @ 004015b0 ---

int __cdecl _printf(char *_Format,...)

{
  FILE *stream;
  int iVar1;
  
  stream = (*_imp____acrt_iob_func)(1);
  iVar1 = __mingw_vfprintf(stream,_Format,&stack0x00000008);
  return iVar1;
}



// --- Function: _main @ 004015fc ---

int __cdecl _main(int _Argc,char **_Argv,char **_Env)

{
  int iVar1;
  int local_168;
  char local_164;
  undefined1 local_15e [333];
  char local_11;
  
  __main();
  signal(2);
  init_game(&local_168,(int)local_15e);
  local_11 = 'x';
  while ((local_168 == 2 && (_sig_intr != 0))) {
    FUN_00401c61((int)local_15e,local_11);
    _printf("\x1b[1;1H\x1b[2J");
    print_board((int)local_15e);
    check_game_state(&local_168,(int)local_15e);
    if (local_11 == 'x') {
      local_11 = 'o';
    }
    else {
      local_11 = 'x';
    }
  }
  if (local_168 == 0) {
    iVar1 = toupper((int)local_164);
    _printf("%c victory!\n\n",iVar1);
  }
  else if (local_168 == 1) {
    _printf("Draw!\n\n");
  }
  getchar();
  return 0;
}



// --- Function: _scanf @ 00401700 ---

int __cdecl _scanf(char *_Format,...)

{
  FILE *s;
  int iVar1;
  
  s = (*_imp____acrt_iob_func)(0);
  iVar1 = __mingw_vfscanf(s,_Format,&stack0x00000008);
  return iVar1;
}



// --- Function: _printf @ 0040173c ---

int __cdecl _printf(char *_Format,...)

{
  FILE *stream;
  int iVar1;
  
  stream = (*_imp____acrt_iob_func)(1);
  iVar1 = __mingw_vfprintf(stream,_Format,&stack0x00000008);
  return iVar1;
}



// --- Function: FUN_00401778 @ 00401778 ---

undefined4 __cdecl FUN_00401778(int param_1,int param_2,int param_3,int param_4)

{
  undefined4 uVar1;
  
  if (*(char *)(param_2 * 0x25 + param_1 + 0x24) == ' ') {
    uVar1 = 0;
  }
  else if ((*(char *)(param_2 * 0x25 + param_1 + 0x24) == *(char *)(param_3 * 0x25 + param_1 + 0x24)
           ) && (*(char *)(param_3 * 0x25 + param_1 + 0x24) ==
                 *(char *)(param_4 * 0x25 + param_1 + 0x24))) {
    uVar1 = 1;
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}



// --- Function: init_square @ 00401822 ---

/* init_square */

void __cdecl init_square(int param_1)

{
  undefined4 local_c;
  undefined4 local_8;
  
  for (local_8 = 0; local_8 < 6; local_8 = local_8 + 1) {
    for (local_c = 0; local_c < 6; local_c = local_c + 1) {
      if ((((local_8 == 0) || (local_8 == 5)) || (local_c == 0)) || (local_c == 5)) {
        *(undefined1 *)(local_c + param_1 + local_8 * 6) = 0x2e;
      }
      else {
        *(undefined1 *)(local_c + param_1 + local_8 * 6) = 0x20;
      }
    }
  }
  *(undefined1 *)(param_1 + 0x24) = 0x20;
  return;
}



// --- Function: FUN_004018a4 @ 004018a4 ---

void __cdecl FUN_004018a4(int param_1)

{
  undefined4 local_c;
  undefined4 local_8;
  
  for (local_8 = 1; local_8 < 5; local_8 = local_8 + 1) {
    for (local_c = 1; local_c < 5; local_c = local_c + 1) {
      if ((local_8 == local_c) || (local_c == 5 - local_8)) {
        *(undefined1 *)(local_c + param_1 + local_8 * 6) = 0x78;
      }
    }
  }
  *(undefined1 *)(param_1 + 0x24) = 0x78;
  return;
}



// --- Function: FUN_00401908 @ 00401908 ---

void __cdecl FUN_00401908(int param_1)

{
  undefined4 local_c;
  
  *(undefined1 *)(param_1 + 0x1b) = 0x6f;
  *(undefined1 *)(param_1 + 9) = *(undefined1 *)(param_1 + 0x1b);
  *(undefined1 *)(param_1 + 0x1a) = *(undefined1 *)(param_1 + 9);
  *(undefined1 *)(param_1 + 8) = *(undefined1 *)(param_1 + 0x1a);
  *(undefined1 *)(param_1 + 0x16) = *(undefined1 *)(param_1 + 8);
  *(undefined1 *)(param_1 + 0x10) = *(undefined1 *)(param_1 + 0x16);
  *(undefined1 *)(param_1 + 0x13) = *(undefined1 *)(param_1 + 0x10);
  *(undefined1 *)(param_1 + 0xd) = *(undefined1 *)(param_1 + 0x13);
  for (local_c = 3; local_c < 3; local_c = local_c + 1) {
    *(undefined1 *)(local_c + param_1) = 0x6f;
    *(undefined1 *)(local_c + param_1 + 0x1e) = 0x6f;
  }
  return;
}



// --- Function: FUN_00401aae @ 00401aae ---

void __cdecl FUN_00401aae(int param_1,char param_2)

{
  if (*(char *)(param_1 + 0x24) == ' ') {
    if ((param_2 == 'x') || (param_2 == 'o')) {
      if (param_2 == 'x') {
        FUN_004018a4(param_1);
      }
      if (param_2 == 'o') {
        FUN_00401908(param_1);
      }
      *(char *)(param_1 + 0x24) = param_2;
    }
    else {
      _printf("Error: Invalid symbol %c\n\n",(int)param_2);
    }
  }
  else {
    _printf("Error: Square already assigned %c\n\n",(int)*(char *)(param_1 + 0x24));
  }
  return;
}



// --- Function: init_board @ 00401b31 ---

/* init_board */

void __cdecl init_board(int param_1)

{
  undefined4 local_8;
  
  for (local_8 = 0; local_8 < 9; local_8 = local_8 + 1) {
    init_square(local_8 * 0x25 + param_1);
  }
  return;
}



// --- Function: FUN_00401b6a @ 00401b6a ---

void __cdecl FUN_00401b6a(int param_1,int param_2,char param_3)

{
  FUN_00401aae(param_2 * 0x25 + param_1,param_3);
  return;
}



// --- Function: print_board @ 00401b9d ---

/* print_board */

void __cdecl print_board(int param_1)

{
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  
  for (local_10 = 0; local_10 < 3; local_10 = local_10 + 1) {
    for (local_14 = 0; local_14 < 6; local_14 = local_14 + 1) {
      for (local_18 = local_10 * 3; local_18 < (local_10 + 1) * 3; local_18 = local_18 + 1) {
        for (local_1c = 0; local_1c < 6; local_1c = local_1c + 1) {
          putchar((int)*(char *)(local_1c + param_1 + local_18 * 0x25 + local_14 * 6));
        }
      }
      putchar(10);
    }
  }
  putchar(10);
  return;
}



// --- Function: FUN_00401c61 @ 00401c61 ---

void __cdecl FUN_00401c61(int param_1,char param_2)

{
  int iVar1;
  int local_14;
  int local_10;
  
  local_10 = 0;
  local_14 = -1;
  while (local_10 != 1) {
    iVar1 = toupper((int)param_2);
    _printf("Provide a move for symbol %c:\n\n",iVar1);
    _printf("1 | 2 | 3\n4 | 5 | 6\n7 | 8 | 9\n\n");
    local_10 = _scanf("%d",&local_14);
    do {
      iVar1 = getchar();
    } while (iVar1 != 10);
    putchar(10);
    if (((local_10 == 1) && (0 < local_14)) && (local_14 < 10)) {
      if (*(char *)((local_14 + -1) * 0x25 + param_1 + 0x24) != ' ') {
        iVar1 = toupper((int)*(char *)((local_14 + -1) * 0x25 + param_1 + 0x24));
        _printf("Error: Square already filled by %c\n\n",iVar1);
        local_10 = 0;
      }
    }
    else {
      _printf("Error: Invalid input - Try again\n\n");
      local_10 = 0;
    }
  }
  FUN_00401b6a(param_1,local_14 + -1,param_2);
  return;
}



// --- Function: init_game @ 00401d93 ---

/* init_game */

void __cdecl init_game(undefined4 *param_1,int param_2)

{
  init_board(param_2);
  *param_1 = 2;
  *(undefined1 *)(param_1 + 1) = 0x20;
  return;
}



// --- Function: FUN_00401db7 @ 00401db7 ---

void __cdecl FUN_00401db7(int param_1)

{
  byte local_18 [16];
  int local_8;
  
  local_18[0] = 6;
  local_18[1] = 0xc6;
  local_18[2] = 0xe7;
  local_18[3] = 0x97;
  local_18[4] = 0x86;
  local_18[5] = 0xf7;
  local_18[6] = 0xd3;
  local_18[7] = 0xb6;
  local_18[8] = 0x95;
  local_18[9] = 0x56;
  local_18[10] = 0x46;
  local_18[0xb] = 0xe7;
  local_18[0xc] = 0xd3;
  local_18[0xd] = 0x36;
  local_18[0xe] = 0x86;
  local_18[0xf] = 0xd0;
  for (local_8 = 0; local_8 < 0x10; local_8 = local_8 + 1) {
    *(byte *)(param_1 + local_8) = (local_18[local_8] >> 4 | local_18[local_8] << 4) ^ 0xd;
  }
  return;
}



// --- Function: check_game_state @ 00401e22 ---

/* check_game_state */

void __cdecl check_game_state(undefined4 *param_1,int param_2)

{
  int iVar1;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  int local_20;
  int local_1c;
  int local_18;
  int local_14;
  int local_10;
  
  for (local_10 = 0; local_10 < 9; local_10 = local_10 + 3) {
    iVar1 = FUN_00401778(param_2,local_10,local_10 + 1,local_10 + 2);
    if (iVar1 != 0) {
      *param_1 = 0;
      *(undefined1 *)(param_1 + 1) = *(undefined1 *)(local_10 * 0x25 + param_2 + 0x24);
      return;
    }
  }
  for (local_14 = 0; local_14 < 3; local_14 = local_14 + 1) {
    iVar1 = FUN_00401778(param_2,local_14,local_14 + 3,local_14 + 6);
    if (iVar1 != 0) {
      *param_1 = 0;
      *(undefined1 *)(param_1 + 1) = *(undefined1 *)(local_14 * 0x25 + param_2 + 0x24);
      return;
    }
  }
  iVar1 = FUN_00401778(param_2,0,4,8);
  if ((iVar1 == 0) && (iVar1 = FUN_00401778(param_2,2,4,6), iVar1 == 0)) {
    local_18 = 0;
    local_20 = (int)*(char *)(param_2 + 0x24);
    local_1c = 0;
    while( true ) {
      if (8 < local_1c) {
        if (local_18 == 9) {
          local_30 = 0;
          local_2c = 0;
          local_28 = 0;
          local_24 = 0;
          FUN_00401db7((int)&local_30);
          _printf("%s\n\n",&local_30);
        }
        *param_1 = 1;
        return;
      }
      if (*(char *)(local_1c * 0x25 + param_2 + 0x24) == ' ') break;
      if (local_20 == *(char *)(local_1c * 0x25 + param_2 + 0x24)) {
        local_18 = local_18 + 1;
      }
      local_1c = local_1c + 1;
    }
    *param_1 = 2;
    return;
  }
  *param_1 = 0;
  *(undefined1 *)(param_1 + 1) = *(undefined1 *)(param_2 + 0xb8);
  return;
}



// --- Function: __do_global_dtors @ 00402030 ---

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void __do_global_dtors(void)

{
  func_ptr *pp_Var1;
  func_ptr p_Var2;
  
  p_Var2 = *__do_global_dtors::p;
  if (p_Var2 == (func_ptr)0x0) {
    return;
  }
  do {
    (*p_Var2)();
    pp_Var1 = __do_global_dtors::p + 1;
    p_Var2 = __do_global_dtors::p[1];
    __do_global_dtors::p = pp_Var1;
  } while (p_Var2 != (func_ptr)0x0);
  return;
}



// --- Function: __do_global_ctors @ 00402070 ---

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void __do_global_ctors(void)

{
  int iVar1;
  int iVar2;
  
                    /* Unresolved local var: ulong nptrs@[???]
                       Unresolved local var: ulong i@[???] */
  iVar2 = ___CTOR_LIST__;
  if (___CTOR_LIST__ == -1) {
    iVar1 = 0;
    do {
      iVar2 = iVar1;
      iVar1 = iVar2 + 1;
    } while ((&___CTOR_LIST__)[iVar2 + 1] != 0);
  }
  for (; iVar2 != 0; iVar2 = iVar2 + -1) {
    (*(code *)(&___CTOR_LIST__)[iVar2])();
  }
  atexit(__do_global_dtors);
  return;
}



// --- Function: __main @ 004020d0 ---

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void __main(void)

{
  if (initialized != 0) {
    return;
  }
  initialized = 1;
  __do_global_ctors();
  return;
}



// --- Function: _setargv @ 004020f0 ---

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int _setargv(void)

{
  return 0;
}



// --- Function: __dyn_tls_dtor @ 00402100 ---

/* WARNING: Unknown calling convention */

BOOL __dyn_tls_dtor(HANDLE hDllHandle,DWORD dwReason,LPVOID lpreserved)

{
  if ((dwReason != 3) && (dwReason != 0)) {
    return 1;
  }
  __mingw_TLScallback(hDllHandle,dwReason,lpreserved);
  return 1;
}



// --- Function: __dyn_tls_init @ 00402150 ---

/* WARNING: Removing unreachable block (ram,0x00402196) */
/* WARNING: Removing unreachable block (ram,0x004021a0) */
/* WARNING: Removing unreachable block (ram,0x004021a6) */
/* WARNING: Removing unreachable block (ram,0x004021a8) */
/* WARNING: Removing unreachable block (ram,0x004021af) */
/* WARNING: Unknown calling convention */

BOOL __dyn_tls_init(HANDLE hDllHandle,DWORD dwReason,LPVOID lpreserved)

{
                    /* Unresolved local var: _PVFV * pfunc@[???]
                       Unresolved local var: uintptr_t ps@[???] */
  if (_CRT_MT != 2) {
    _CRT_MT = 2;
  }
  if ((dwReason != 2) && (dwReason == 1)) {
    __mingw_TLScallback(hDllHandle,1,lpreserved);
    return 1;
  }
  return 1;
}



// --- Function: __tlregdtor @ 004021f0 ---

/* WARNING: Unknown calling convention */

int __tlregdtor(_PVFV func)

{
  return 0;
}



// --- Function: _matherr @ 00402200 ---

/* WARNING: Unknown calling convention */

int _matherr(_exception *pexcept)

{
  FILE *pFVar1;
  
                    /* Unresolved local var: char * type@[???] */
  pFVar1 = __acrt_iob_func(2);
  fprintf((FILE *)pFVar1,"_matherr(): %s in %s(%g, %g)  (retval=%g)\n");
  return 0;
}



// --- Function: _fpreset @ 00402280 ---

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void _fpreset(void)

{
  return;
}



// --- Function: __report_error @ 00402290 ---

/* WARNING: Unknown calling convention */

void __report_error(char *msg,...)

{
  FILE *pFVar1;
  
                    /* Unresolved local var: va_list argp@[???] */
  pFVar1 = __acrt_iob_func(2);
  fwrite("Mingw-w64 runtime failure:\n",1,0x1b,(FILE *)pFVar1);
  pFVar1 = __acrt_iob_func(2);
  vfprintf((FILE *)pFVar1,msg,&stack0x00000008);
                    /* WARNING: Subroutine does not return */
  abort();
}



// --- Function: mark_section_writable @ 004022f0 ---

void __cdecl mark_section_writable(LPVOID addr)

{
  DWORD DVar1;
  PBYTE in_EAX;
  PBYTE *ppBVar2;
  PIMAGE_SECTION_HEADER p_Var3;
  sSecInfo *psVar4;
  PBYTE pBVar5;
  SIZE_T SVar6;
  DWORD DVar7;
  BOOL BVar8;
  int iVar9;
  int iVar10;
  MEMORY_BASIC_INFORMATION b;
  
                    /* Unresolved local var: PIMAGE_SECTION_HEADER h@[???]
                       Unresolved local var: int i@[???] */
  if (maxSections < 1) {
    iVar10 = 0;
  }
  else {
    iVar9 = 0;
    ppBVar2 = &the_secs->sec_start;
    do {
      if ((*ppBVar2 <= in_EAX) &&
         (in_EAX < *ppBVar2 + (((PIMAGE_SECTION_HEADER)ppBVar2[1])->Misc).PhysicalAddress)) {
        return;
      }
      iVar9 = iVar9 + 1;
      ppBVar2 = ppBVar2 + 5;
      iVar10 = maxSections;
    } while (iVar9 != maxSections);
  }
  p_Var3 = __mingw_GetSectionForAddress(in_EAX);
  if (p_Var3 == (PIMAGE_SECTION_HEADER)0x0) {
                    /* WARNING: Subroutine does not return */
    __report_error("Address %p has no image-section");
  }
  psVar4 = the_secs + iVar10;
  psVar4->hash = p_Var3;
  psVar4->old_protect = 0;
  pBVar5 = _GetPEImageBase();
  DVar1 = p_Var3->VirtualAddress;
  the_secs[iVar10].sec_start = pBVar5 + DVar1;
  SVar6 = VirtualQuery(pBVar5 + DVar1,(PMEMORY_BASIC_INFORMATION)&b,0x1c);
  if (SVar6 != 0) {
    if (((b.Protect - 0x40 & 0xffffffbf) != 0) && ((b.Protect - 4 & 0xfffffffb) != 0)) {
                    /* Unresolved local var: ULONG new_protect@[???] */
      DVar7 = 0x40;
      if (b.Protect == 2) {
        DVar7 = 4;
      }
      psVar4 = the_secs + iVar10;
      psVar4->region_size = b.RegionSize;
      psVar4->base_address = b.BaseAddress;
      BVar8 = VirtualProtect(b.BaseAddress,b.RegionSize,DVar7,&psVar4->old_protect);
      if (BVar8 == 0) {
        DVar7 = GetLastError();
                    /* WARNING: Subroutine does not return */
        __report_error("  VirtualProtect failed with code 0x%x",DVar7);
      }
    }
    maxSections = maxSections + 1;
    return;
  }
                    /* WARNING: Subroutine does not return */
  __report_error("  VirtualQuery failed for %d bytes at address %p",(p_Var3->Misc).PhysicalAddress,
                 the_secs[iVar10].sec_start);
}



// --- Function: _pei386_runtime_relocator @ 00402450 ---

/* WARNING: Unable to track spacebase fully for stack */
/* WARNING: Removing unreachable block (ram,0x004024bb) */
/* WARNING: Removing unreachable block (ram,0x004024ca) */
/* WARNING: Removing unreachable block (ram,0x00402580) */
/* WARNING: Removing unreachable block (ram,0x00402588) */
/* WARNING: Removing unreachable block (ram,0x004024cf) */
/* WARNING: Removing unreachable block (ram,0x004024d9) */
/* WARNING: Removing unreachable block (ram,0x004025a0) */
/* WARNING: Removing unreachable block (ram,0x004024dc) */
/* WARNING: Removing unreachable block (ram,0x004024e4) */
/* WARNING: Removing unreachable block (ram,0x0040273f) */
/* WARNING: Removing unreachable block (ram,0x004024f0) */
/* WARNING: Removing unreachable block (ram,0x004024ff) */
/* WARNING: Removing unreachable block (ram,0x00402508) */
/* WARNING: Removing unreachable block (ram,0x004025d0) */
/* WARNING: Removing unreachable block (ram,0x004025e2) */
/* WARNING: Removing unreachable block (ram,0x004025e7) */
/* WARNING: Removing unreachable block (ram,0x004025f2) */
/* WARNING: Removing unreachable block (ram,0x004025fe) */
/* WARNING: Removing unreachable block (ram,0x0040260a) */
/* WARNING: Removing unreachable block (ram,0x00402534) */
/* WARNING: Removing unreachable block (ram,0x004025b0) */
/* WARNING: Removing unreachable block (ram,0x004025b9) */
/* WARNING: Removing unreachable block (ram,0x00402690) */
/* WARNING: Removing unreachable block (ram,0x004026a1) */
/* WARNING: Removing unreachable block (ram,0x004026a6) */
/* WARNING: Removing unreachable block (ram,0x004026b1) */
/* WARNING: Removing unreachable block (ram,0x004026bd) */
/* WARNING: Removing unreachable block (ram,0x004026c6) */
/* WARNING: Removing unreachable block (ram,0x00402539) */
/* WARNING: Removing unreachable block (ram,0x00402552) */
/* WARNING: Removing unreachable block (ram,0x0040255a) */
/* WARNING: Removing unreachable block (ram,0x004026e0) */
/* WARNING: Removing unreachable block (ram,0x00402619) */
/* WARNING: Removing unreachable block (ram,0x00402628) */
/* WARNING: Removing unreachable block (ram,0x004026f8) */
/* WARNING: Removing unreachable block (ram,0x004026fd) */
/* WARNING: Removing unreachable block (ram,0x00402709) */
/* WARNING: Removing unreachable block (ram,0x00402710) */
/* WARNING: Removing unreachable block (ram,0x00402737) */
/* WARNING: Removing unreachable block (ram,0x0040262b) */
/* WARNING: Removing unreachable block (ram,0x00402639) */
/* WARNING: Removing unreachable block (ram,0x00402648) */
/* WARNING: Removing unreachable block (ram,0x0040265a) */
/* WARNING: Removing unreachable block (ram,0x00402674) */
/* WARNING: Removing unreachable block (ram,0x0040267f) */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void _pei386_runtime_relocator(void)

{
  uint uVar1;
  undefined1 auStack_39 [25];
  DWORD oldprot;
  
                    /* Unresolved local var: int mSecs@[???] */
  if (_pei386_runtime_relocator::was_init == 0) {
    _pei386_runtime_relocator::was_init = 1;
    __mingw_GetSectionCount();
    uVar1 = ___chkstk_ms();
    maxSections = 0;
    the_secs = (sSecInfo *)((uint)(auStack_39 + -uVar1) & 0xfffffff0);
                    /* Unresolved local var: ptrdiff_t addr_imp@[???]
                       Unresolved local var: ptrdiff_t reldata@[???]
                       Unresolved local var: ptrdiff_t reloc_target@[???]
                       Unresolved local var: runtime_pseudo_reloc_v2 * v2_hdr@[???]
                       Unresolved local var: runtime_pseudo_reloc_item_v2 * r@[???]
                       Unresolved local var: uint bits@[???] */
  }
  return;
}



// --- Function: __mingw_raise_matherr @ 00402750 ---

/* WARNING: Unknown calling convention */

void __mingw_raise_matherr(int typ,char *name,double a1,double a2,double rslt)

{
  _exception ex;
  
  if (stUserMathErr != (fUserMathErr)0x0) {
    ex.arg1 = a1;
    ex.arg2 = a2;
    ex.type = typ;
    ex.retval = rslt;
    ex.name = name;
    (*stUserMathErr)(&ex);
  }
  return;
}



// --- Function: __mingw_setusermatherr @ 004027b0 ---

/* WARNING: Unknown calling convention */

void __mingw_setusermatherr(_func_int__exception_ptr *f)

{
  stUserMathErr = f;
  ___setusermatherr();
  return;
}



// --- Function: _gnu_exception_handler @ 004027c0 ---

/* WARNING: Unknown calling convention */

long _gnu_exception_handler(EXCEPTION_POINTERS *exception_data)

{
  uint uVar1;
  code *pcVar2;
  LONG LVar3;
  undefined4 uVar4;
  
                    /* Unresolved local var: _func_void_int * old_handler@[???]
                       Unresolved local var: long action@[???]
                       Unresolved local var: int reset_fpu@[???] */
  uVar1 = exception_data->ExceptionRecord->ExceptionCode;
  if (uVar1 == 0xc0000093) {
LAB_004027f0:
    uVar4 = 0;
    pcVar2 = (code *)signal(8);
    if (pcVar2 == (code *)0x1) {
      signal(8);
      _fpreset();
      return -1;
    }
LAB_0040280d:
    if (pcVar2 != (code *)0x0) {
      (*pcVar2)(8,uVar4);
      return -1;
    }
  }
  else {
    if (uVar1 < 0xc0000094) {
      if (uVar1 != 0xc000001d) {
        if (uVar1 < 0xc000001e) {
          if (uVar1 == 0xc0000005) {
            uVar4 = 0;
            pcVar2 = (code *)signal(0xb);
            if (pcVar2 == (code *)0x1) {
              signal(0xb);
              return -1;
            }
            if (pcVar2 != (code *)0x0) {
              (*pcVar2)(0xb,uVar4);
              return -1;
            }
          }
          goto LAB_00402815;
        }
        if (4 < uVar1 + 0x3fffff73) goto LAB_00402815;
        goto LAB_004027f0;
      }
    }
    else {
      if (uVar1 == 0xc0000094) {
        uVar4 = 0;
        pcVar2 = (code *)signal(8);
        if (pcVar2 == (code *)0x1) {
          signal(8);
          return -1;
        }
        goto LAB_0040280d;
      }
      if (uVar1 != 0xc0000096) goto LAB_00402815;
    }
    uVar4 = 0;
    pcVar2 = (code *)signal(4);
    if (pcVar2 == (code *)0x1) {
      signal(4);
      return -1;
    }
    if (pcVar2 != (code *)0x0) {
      (*pcVar2)(4,uVar4);
      return -1;
    }
  }
LAB_00402815:
  if (__mingw_oldexcpt_handler != (LPTOP_LEVEL_EXCEPTION_FILTER)0x0) {
                    /* WARNING: Could not recover jumptable at 0x0040282a. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    LVar3 = (*__mingw_oldexcpt_handler)(exception_data);
    return LVar3;
  }
  return 0;
}



// --- Function: __mingwthr_run_key_dtors @ 00402950 ---

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void __mingwthr_run_key_dtors(void)

{
  __mingwthr_key_t *p_Var1;
  LPVOID pvVar2;
  DWORD DVar3;
  
                    /* Unresolved local var: __mingwthr_key_t * keyp@[???] */
  EnterCriticalSection((LPCRITICAL_SECTION)&__mingwthr_cs);
  for (p_Var1 = key_dtor_list; p_Var1 != (__mingwthr_key_t *)0x0; p_Var1 = p_Var1->next) {
                    /* Unresolved local var: LPVOID value@[???] */
    pvVar2 = TlsGetValue(p_Var1->key);
    DVar3 = GetLastError();
    if ((DVar3 == 0) && (pvVar2 != (LPVOID)0x0)) {
      (*p_Var1->dtor)(pvVar2);
    }
  }
  LeaveCriticalSection((LPCRITICAL_SECTION)&__mingwthr_cs);
  return;
}



// --- Function: ___w64_mingwthr_add_key_dtor @ 004029c0 ---

/* WARNING: Unknown calling convention */

int ___w64_mingwthr_add_key_dtor(DWORD key,_func_void_void_ptr *dtor)

{
  __mingwthr_key_t *p_Var1;
  int iVar2;
  
                    /* Unresolved local var: __mingwthr_key_t * new_key@[???] */
  if (__mingwthr_cs_init == 0) {
    return 0;
  }
  p_Var1 = (__mingwthr_key_t *)calloc(1,0xc);
  if (p_Var1 == (__mingwthr_key_t *)0x0) {
    iVar2 = -1;
  }
  else {
    p_Var1->key = key;
    p_Var1->dtor = dtor;
    EnterCriticalSection((LPCRITICAL_SECTION)&__mingwthr_cs);
    p_Var1->next = key_dtor_list;
    key_dtor_list = p_Var1;
    LeaveCriticalSection((LPCRITICAL_SECTION)&__mingwthr_cs);
    iVar2 = 0;
  }
  return iVar2;
}



// --- Function: ___w64_mingwthr_remove_key_dtor @ 00402a40 ---

/* WARNING: Unknown calling convention */

int ___w64_mingwthr_remove_key_dtor(DWORD key)

{
  __mingwthr_key_t *p_Var1;
  __mingwthr_key_t *p_Var2;
  __mingwthr_key_t *p_Var3;
  
                    /* Unresolved local var: __mingwthr_key_t * prev_key@[???]
                       Unresolved local var: __mingwthr_key_t * cur_key@[???] */
  if (__mingwthr_cs_init == 0) {
    return 0;
  }
  EnterCriticalSection((LPCRITICAL_SECTION)&__mingwthr_cs);
  if (key_dtor_list != (__mingwthr_key_t *)0x0) {
    p_Var1 = key_dtor_list;
    p_Var3 = (__mingwthr_key_t *)0x0;
    do {
      p_Var2 = p_Var1;
      p_Var1 = p_Var2->next;
      if (p_Var2->key == key) {
        if (p_Var3 != (__mingwthr_key_t *)0x0) {
          p_Var3->next = p_Var1;
          p_Var1 = key_dtor_list;
        }
        key_dtor_list = p_Var1;
        free(p_Var2);
        break;
      }
      p_Var3 = p_Var2;
    } while (p_Var1 != (__mingwthr_key_t *)0x0);
  }
  LeaveCriticalSection((LPCRITICAL_SECTION)&__mingwthr_cs);
  return 0;
}



// --- Function: __mingw_TLScallback @ 00402ad0 ---

/* WARNING: Unknown calling convention */

WINBOOL __mingw_TLScallback(HANDLE hDllHandle,DWORD reason,LPVOID reserved)

{
  __mingwthr_key_t *p_Var1;
  __mingwthr_key_t *p_Var2;
  
  if (reason != 2) {
    if (reason < 3) {
      if (reason == 0) {
                    /* Unresolved local var: __mingwthr_key_t * keyp@[???] */
        if (__mingwthr_cs_init != 0) {
          __mingwthr_run_key_dtors();
        }
        if (__mingwthr_cs_init == 1) {
          __mingwthr_cs_init = 1;
          p_Var2 = key_dtor_list;
          while (p_Var2 != (__mingwthr_key_t *)0x0) {
            p_Var1 = p_Var2->next;
            free(p_Var2);
            p_Var2 = p_Var1;
          }
          key_dtor_list = (__mingwthr_key_t *)0x0;
          __mingwthr_cs_init = 0;
          DeleteCriticalSection((LPCRITICAL_SECTION)&__mingwthr_cs);
        }
      }
      else {
        if (__mingwthr_cs_init == 0) {
          InitializeCriticalSection((LPCRITICAL_SECTION)&__mingwthr_cs);
        }
        __mingwthr_cs_init = 1;
      }
    }
    else {
                    /* Unresolved local var: __mingwthr_key_t * keyp@[???] */
      if ((reason == 3) && (__mingwthr_cs_init != 0)) {
        __mingwthr_run_key_dtors();
      }
    }
    return 1;
  }
  _fpreset();
  return 1;
}



// --- Function: _ValidateImageBase @ 00402bd0 ---

/* WARNING: Unknown calling convention */

WINBOOL _ValidateImageBase(PBYTE pImageBase)

{
                    /* Unresolved local var: PIMAGE_DOS_HEADER pDOSHeader@[???]
                       Unresolved local var: PIMAGE_NT_HEADERS pNTHeader@[???]
                       Unresolved local var: PIMAGE_OPTIONAL_HEADER pOptHeader@[???] */
                    /* Unresolved local var: PIMAGE_DOS_HEADER pDOSHeader@[???]
                       Unresolved local var: PIMAGE_NT_HEADERS pNTHeader@[???]
                       Unresolved local var: PIMAGE_OPTIONAL_HEADER pOptHeader@[???] */
  if ((*(short *)pImageBase == 0x5a4d) &&
     (*(int *)(pImageBase + *(int *)(pImageBase + 0x3c)) == 0x4550)) {
    return (uint)((short)*(int *)((int)(pImageBase + *(int *)(pImageBase + 0x3c)) + 0x18) == 0x10b);
  }
  return 0;
}



// --- Function: _FindPESection @ 00402c00 ---

/* WARNING: Unknown calling convention */

PIMAGE_SECTION_HEADER _FindPESection(PBYTE pImageBase,DWORD_PTR rva)

{
  int iVar1;
  PIMAGE_SECTION_HEADER p_Var2;
  uint uVar3;
  
                    /* Unresolved local var: PIMAGE_NT_HEADERS pNTHeader@[???]
                       Unresolved local var: PIMAGE_SECTION_HEADER pSection@[???]
                       Unresolved local var: uint iSection@[???] */
  iVar1 = *(int *)(pImageBase + 0x3c);
  p_Var2 = (PIMAGE_SECTION_HEADER)
           (pImageBase + (uint)*(ushort *)(pImageBase + iVar1 + 0x14) + iVar1 + 0x18);
  if (*(ushort *)(pImageBase + iVar1 + 6) != 0) {
    uVar3 = 0;
    do {
      if ((p_Var2->VirtualAddress <= rva) &&
         (rva < p_Var2->VirtualAddress + (p_Var2->Misc).PhysicalAddress)) {
        return p_Var2;
      }
      uVar3 = uVar3 + 1;
      p_Var2 = p_Var2 + 1;
    } while (uVar3 != *(ushort *)(pImageBase + iVar1 + 6));
  }
  return (PIMAGE_SECTION_HEADER)0x0;
}



// --- Function: _FindPESectionByName @ 00402c40 ---

/* WARNING: Unknown calling convention */

PIMAGE_SECTION_HEADER _FindPESectionByName(char *pName)

{
  ushort uVar1;
  uint uVar2;
  int iVar3;
  PIMAGE_SECTION_HEADER p_Var4;
  
                    /* Unresolved local var: PBYTE pImageBase@[???]
                       Unresolved local var: PIMAGE_NT_HEADERS pNTHeader@[???]
                       Unresolved local var: PIMAGE_SECTION_HEADER pSection@[???]
                       Unresolved local var: uint iSection@[???] */
  uVar2 = strlen(pName);
                    /* Unresolved local var: PIMAGE_DOS_HEADER pDOSHeader@[???]
                       Unresolved local var: PIMAGE_NT_HEADERS pNTHeader@[???]
                       Unresolved local var: PIMAGE_OPTIONAL_HEADER pOptHeader@[???] */
                    /* Unresolved local var: PIMAGE_DOS_HEADER pDOSHeader@[???]
                       Unresolved local var: PIMAGE_NT_HEADERS pNTHeader@[???]
                       Unresolved local var: PIMAGE_OPTIONAL_HEADER pOptHeader@[???] */
  if ((((uVar2 < 9) && (IMAGE_DOS_HEADER_00400000.e_magic == (char  [2])0x5a4d)) &&
      (*(int *)(IMAGE_DOS_HEADER_00400000.e_lfanew + 0x400000) == 0x4550)) &&
     (*(short *)((int)IMAGE_DOS_HEADER_00400000.e_res_4_ + (IMAGE_DOS_HEADER_00400000.e_lfanew - 4))
      == 0x10b)) {
    uVar1 = *(ushort *)(IMAGE_DOS_HEADER_00400000.e_magic + IMAGE_DOS_HEADER_00400000.e_lfanew + 6);
    p_Var4 = (PIMAGE_SECTION_HEADER)
             (IMAGE_DOS_HEADER_00400000.e_lfanew + 0x400018 +
             (uint)*(ushort *)
                    ((int)IMAGE_DOS_HEADER_00400000.e_res_4_ +
                    (IMAGE_DOS_HEADER_00400000.e_lfanew - 8)));
    if (uVar1 != 0) {
      uVar2 = 0;
      do {
        iVar3 = strncmp((char *)p_Var4,pName,8);
        if (iVar3 == 0) {
          return p_Var4;
        }
        uVar2 = uVar2 + 1;
        p_Var4 = p_Var4 + 1;
      } while (uVar1 != uVar2);
    }
    return (PIMAGE_SECTION_HEADER)0x0;
  }
  return (PIMAGE_SECTION_HEADER)0x0;
}



// --- Function: __mingw_GetSectionForAddress @ 00402ce0 ---

/* WARNING: Unknown calling convention */

PIMAGE_SECTION_HEADER __mingw_GetSectionForAddress(LPVOID p)

{
  PIMAGE_SECTION_HEADER p_Var1;
  uint uVar2;
  
                    /* Unresolved local var: PBYTE pImageBase@[???]
                       Unresolved local var: DWORD_PTR rva@[???]
                       Unresolved local var: PIMAGE_DOS_HEADER pDOSHeader@[???]
                       Unresolved local var: PIMAGE_NT_HEADERS pNTHeader@[???]
                       Unresolved local var: PIMAGE_OPTIONAL_HEADER pOptHeader@[???] */
                    /* Unresolved local var: PIMAGE_DOS_HEADER pDOSHeader@[???]
                       Unresolved local var: PIMAGE_NT_HEADERS pNTHeader@[???]
                       Unresolved local var: PIMAGE_OPTIONAL_HEADER pOptHeader@[???] */
  if (((IMAGE_DOS_HEADER_00400000.e_magic == (char  [2])0x5a4d) &&
      (*(int *)(IMAGE_DOS_HEADER_00400000.e_lfanew + 0x400000) == 0x4550)) &&
     (*(short *)((int)IMAGE_DOS_HEADER_00400000.e_res_4_ + (IMAGE_DOS_HEADER_00400000.e_lfanew - 4))
      == 0x10b)) {
                    /* Unresolved local var: PIMAGE_NT_HEADERS pNTHeader@[???]
                       Unresolved local var: PIMAGE_SECTION_HEADER pSection@[???]
                       Unresolved local var: uint iSection@[???] */
    p_Var1 = (PIMAGE_SECTION_HEADER)
             (IMAGE_DOS_HEADER_00400000.e_lfanew + 0x400018 +
             (uint)*(ushort *)
                    ((int)IMAGE_DOS_HEADER_00400000.e_res_4_ +
                    (IMAGE_DOS_HEADER_00400000.e_lfanew - 8)));
    if (*(ushort *)(IMAGE_DOS_HEADER_00400000.e_magic + IMAGE_DOS_HEADER_00400000.e_lfanew + 6) != 0
       ) {
      uVar2 = 0;
      do {
        if ((p_Var1->VirtualAddress <= (int)p - 0x400000U) &&
           ((int)p - 0x400000U < p_Var1->VirtualAddress + (p_Var1->Misc).PhysicalAddress)) {
          return p_Var1;
        }
        uVar2 = uVar2 + 1;
        p_Var1 = p_Var1 + 1;
      } while (uVar2 != *(ushort *)
                         (IMAGE_DOS_HEADER_00400000.e_magic + IMAGE_DOS_HEADER_00400000.e_lfanew + 6
                         ));
    }
    return (PIMAGE_SECTION_HEADER)0x0;
  }
  return (PIMAGE_SECTION_HEADER)0x0;
}



// --- Function: __mingw_GetSectionCount @ 00402d60 ---

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int __mingw_GetSectionCount(void)

{
                    /* Unresolved local var: PBYTE pImageBase@[???]
                       Unresolved local var: PIMAGE_NT_HEADERS pNTHeader@[???]
                       Unresolved local var: PIMAGE_DOS_HEADER pDOSHeader@[???]
                       Unresolved local var: PIMAGE_OPTIONAL_HEADER pOptHeader@[???] */
                    /* Unresolved local var: PIMAGE_DOS_HEADER pDOSHeader@[???]
                       Unresolved local var: PIMAGE_NT_HEADERS pNTHeader@[???]
                       Unresolved local var: PIMAGE_OPTIONAL_HEADER pOptHeader@[???] */
  if (((IMAGE_DOS_HEADER_00400000.e_magic == (char  [2])0x5a4d) &&
      (*(int *)(IMAGE_DOS_HEADER_00400000.e_lfanew + 0x400000) == 0x4550)) &&
     (*(short *)((int)IMAGE_DOS_HEADER_00400000.e_res_4_ + (IMAGE_DOS_HEADER_00400000.e_lfanew - 4))
      == 0x10b)) {
    return (uint)*(ushort *)
                  (IMAGE_DOS_HEADER_00400000.e_magic + IMAGE_DOS_HEADER_00400000.e_lfanew + 6);
  }
  return 0;
}



// --- Function: _FindPESectionExec @ 00402da0 ---

/* WARNING: Unknown calling convention */

PIMAGE_SECTION_HEADER _FindPESectionExec(size_t eNo)

{
  PIMAGE_SECTION_HEADER p_Var1;
  uint uVar2;
  
                    /* Unresolved local var: PBYTE pImageBase@[???]
                       Unresolved local var: PIMAGE_NT_HEADERS pNTHeader@[???]
                       Unresolved local var: PIMAGE_SECTION_HEADER pSection@[???]
                       Unresolved local var: uint iSection@[???]
                       Unresolved local var: PIMAGE_DOS_HEADER pDOSHeader@[???]
                       Unresolved local var: PIMAGE_OPTIONAL_HEADER pOptHeader@[???] */
                    /* Unresolved local var: PIMAGE_DOS_HEADER pDOSHeader@[???]
                       Unresolved local var: PIMAGE_NT_HEADERS pNTHeader@[???]
                       Unresolved local var: PIMAGE_OPTIONAL_HEADER pOptHeader@[???] */
  if (((IMAGE_DOS_HEADER_00400000.e_magic == (char  [2])0x5a4d) &&
      (*(int *)(IMAGE_DOS_HEADER_00400000.e_lfanew + 0x400000) == 0x4550)) &&
     (*(short *)((int)IMAGE_DOS_HEADER_00400000.e_res_4_ + (IMAGE_DOS_HEADER_00400000.e_lfanew - 4))
      == 0x10b)) {
    p_Var1 = (PIMAGE_SECTION_HEADER)
             (IMAGE_DOS_HEADER_00400000.e_lfanew + 0x400018 +
             (uint)*(ushort *)
                    ((int)IMAGE_DOS_HEADER_00400000.e_res_4_ +
                    (IMAGE_DOS_HEADER_00400000.e_lfanew - 8)));
    if (*(ushort *)(IMAGE_DOS_HEADER_00400000.e_magic + IMAGE_DOS_HEADER_00400000.e_lfanew + 6) != 0
       ) {
      uVar2 = 0;
      do {
        if ((p_Var1->Characteristics & 0x20000000) != 0) {
          if (eNo == 0) {
            return p_Var1;
          }
          eNo = eNo - 1;
        }
        uVar2 = uVar2 + 1;
        p_Var1 = p_Var1 + 1;
      } while (*(ushort *)
                (IMAGE_DOS_HEADER_00400000.e_magic + IMAGE_DOS_HEADER_00400000.e_lfanew + 6) !=
               uVar2);
    }
    return (PIMAGE_SECTION_HEADER)0x0;
  }
  return (PIMAGE_SECTION_HEADER)0x0;
}



// --- Function: _GetPEImageBase @ 00402e20 ---

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

PBYTE _GetPEImageBase(void)

{
  IMAGE_DOS_HEADER *pIVar1;
  
                    /* Unresolved local var: PBYTE pImageBase@[???]
                       Unresolved local var: PIMAGE_DOS_HEADER pDOSHeader@[???]
                       Unresolved local var: PIMAGE_NT_HEADERS pNTHeader@[???]
                       Unresolved local var: PIMAGE_OPTIONAL_HEADER pOptHeader@[???] */
  pIVar1 = (IMAGE_DOS_HEADER *)0x0;
                    /* Unresolved local var: PIMAGE_DOS_HEADER pDOSHeader@[???]
                       Unresolved local var: PIMAGE_NT_HEADERS pNTHeader@[???]
                       Unresolved local var: PIMAGE_OPTIONAL_HEADER pOptHeader@[???] */
  if ((IMAGE_DOS_HEADER_00400000.e_magic == (char  [2])0x5a4d) &&
     (*(int *)(IMAGE_DOS_HEADER_00400000.e_lfanew + 0x400000) == 0x4550)) {
    if (*(short *)((int)IMAGE_DOS_HEADER_00400000.e_res_4_ +
                  (IMAGE_DOS_HEADER_00400000.e_lfanew - 4)) == 0x10b) {
      pIVar1 = &IMAGE_DOS_HEADER_00400000;
    }
    return (PBYTE)pIVar1;
  }
  return (PBYTE)pIVar1;
}



// --- Function: _IsNonwritableInCurrentImage @ 00402e60 ---

/* WARNING: Unknown calling convention */

WINBOOL _IsNonwritableInCurrentImage(PBYTE pTarget)

{
  int iVar1;
  uint uVar2;
  
                    /* Unresolved local var: PBYTE pImageBase@[???]
                       Unresolved local var: DWORD_PTR rvaTarget@[???]
                       Unresolved local var: PIMAGE_SECTION_HEADER pSection@[???]
                       Unresolved local var: PIMAGE_DOS_HEADER pDOSHeader@[???]
                       Unresolved local var: PIMAGE_NT_HEADERS pNTHeader@[???]
                       Unresolved local var: PIMAGE_OPTIONAL_HEADER pOptHeader@[???] */
                    /* Unresolved local var: PIMAGE_DOS_HEADER pDOSHeader@[???]
                       Unresolved local var: PIMAGE_NT_HEADERS pNTHeader@[???]
                       Unresolved local var: PIMAGE_OPTIONAL_HEADER pOptHeader@[???] */
  if (((IMAGE_DOS_HEADER_00400000.e_magic == (char  [2])0x5a4d) &&
      (*(int *)(IMAGE_DOS_HEADER_00400000.e_lfanew + 0x400000) == 0x4550)) &&
     (*(short *)((int)IMAGE_DOS_HEADER_00400000.e_res_4_ + (IMAGE_DOS_HEADER_00400000.e_lfanew - 4))
      == 0x10b)) {
                    /* Unresolved local var: PIMAGE_NT_HEADERS pNTHeader@[???]
                       Unresolved local var: PIMAGE_SECTION_HEADER pSection@[???]
                       Unresolved local var: uint iSection@[???] */
    iVar1 = IMAGE_DOS_HEADER_00400000.e_lfanew + 0x400018 +
            (uint)*(ushort *)
                   ((int)IMAGE_DOS_HEADER_00400000.e_res_4_ +
                   (IMAGE_DOS_HEADER_00400000.e_lfanew - 8));
    if (*(ushort *)(IMAGE_DOS_HEADER_00400000.e_magic + IMAGE_DOS_HEADER_00400000.e_lfanew + 6) != 0
       ) {
      uVar2 = 0;
      do {
        if ((*(PBYTE *)(iVar1 + 0xc) <= pTarget + -0x400000) &&
           (pTarget + -0x400000 < *(PBYTE *)(iVar1 + 0xc) + *(int *)(iVar1 + 8))) {
          return ~*(uint *)(iVar1 + 0x24) >> 0x1f;
        }
        uVar2 = uVar2 + 1;
        iVar1 = iVar1 + 0x28;
      } while (*(ushort *)
                (IMAGE_DOS_HEADER_00400000.e_magic + IMAGE_DOS_HEADER_00400000.e_lfanew + 6) !=
               uVar2);
    }
    return 0;
  }
  return 0;
}



// --- Function: __mingw_enum_import_library_names @ 00402ef0 ---

/* WARNING: Unknown calling convention */

char * __mingw_enum_import_library_names(int i)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  
                    /* Unresolved local var: PBYTE pImageBase@[???]
                       Unresolved local var: PIMAGE_NT_HEADERS pNTHeader@[???]
                       Unresolved local var: PIMAGE_IMPORT_DESCRIPTOR importDesc@[???]
                       Unresolved local var: PIMAGE_SECTION_HEADER pSection@[???]
                       Unresolved local var: DWORD importsStartRVA@[???]
                       Unresolved local var: PIMAGE_DOS_HEADER pDOSHeader@[???]
                       Unresolved local var: PIMAGE_OPTIONAL_HEADER pOptHeader@[???] */
                    /* Unresolved local var: PIMAGE_DOS_HEADER pDOSHeader@[???]
                       Unresolved local var: PIMAGE_NT_HEADERS pNTHeader@[???]
                       Unresolved local var: PIMAGE_OPTIONAL_HEADER pOptHeader@[???] */
  if ((((IMAGE_DOS_HEADER_00400000.e_magic == (char  [2])0x5a4d) &&
       (*(int *)(IMAGE_DOS_HEADER_00400000.e_lfanew + 0x400000) == 0x4550)) &&
      (*(short *)((int)IMAGE_DOS_HEADER_00400000.e_res_4_ + (IMAGE_DOS_HEADER_00400000.e_lfanew - 4)
                 ) == 0x10b)) &&
     (uVar1 = *(uint *)(IMAGE_NT_HEADERS32_00400080.Signature + IMAGE_DOS_HEADER_00400000.e_lfanew),
     uVar1 != 0)) {
                    /* Unresolved local var: PIMAGE_NT_HEADERS pNTHeader@[???]
                       Unresolved local var: PIMAGE_SECTION_HEADER pSection@[???]
                       Unresolved local var: uint iSection@[???] */
    iVar2 = IMAGE_DOS_HEADER_00400000.e_lfanew + 0x400018 +
            (uint)*(ushort *)
                   ((int)IMAGE_DOS_HEADER_00400000.e_res_4_ +
                   (IMAGE_DOS_HEADER_00400000.e_lfanew - 8));
    if (*(ushort *)(IMAGE_DOS_HEADER_00400000.e_magic + IMAGE_DOS_HEADER_00400000.e_lfanew + 6) != 0
       ) {
      uVar3 = 0;
      while ((uVar1 < *(uint *)(iVar2 + 0xc) ||
             (*(uint *)(iVar2 + 0xc) + *(int *)(iVar2 + 8) <= uVar1))) {
        uVar3 = uVar3 + 1;
        iVar2 = iVar2 + 0x28;
        if (*(ushort *)(IMAGE_DOS_HEADER_00400000.e_magic + IMAGE_DOS_HEADER_00400000.e_lfanew + 6)
            == uVar3) {
          return (char *)0x0;
        }
      }
      for (iVar2 = uVar1 + 0x400000; (*(int *)(iVar2 + 4) != 0 || (*(int *)(iVar2 + 0xc) != 0));
          iVar2 = iVar2 + 0x14) {
        if (i < 1) {
          return (char *)(*(int *)(iVar2 + 0xc) + 0x400000);
        }
        i = i + -1;
      }
      return (char *)0x0;
    }
  }
  return (char *)0x0;
}



// --- Function: ___chkstk_ms @ 00402fb0 ---

uint ___chkstk_ms(void)

{
  uint in_EAX;
  uint uVar1;
  undefined4 *puVar2;
  
  puVar2 = (undefined4 *)&stack0x00000004;
  uVar1 = in_EAX;
  if (0xfff < in_EAX) {
    do {
      puVar2 = puVar2 + -0x400;
      *puVar2 = *puVar2;
      uVar1 = uVar1 - 0x1000;
    } while (0x1000 < uVar1);
  }
  *(undefined4 *)((int)puVar2 - uVar1) = *(undefined4 *)((int)puVar2 - uVar1);
  return in_EAX;
}



// --- Function: __mingw_vfprintf @ 00402fe0 ---

/* WARNING: Unknown calling convention */

int __mingw_vfprintf(FILE *stream,char *fmt,va_list argv)

{
  int iVar1;
  
                    /* Unresolved local var: int retval@[???] */
  _lock_file(stream);
  iVar1 = __mingw_pformat(0x6000,stream,0,fmt,argv);
  _unlock_file(stream);
  return iVar1;
}



// --- Function: optimize_alloc @ 00403030 ---

void __fastcall optimize_alloc(char **p,char *end,size_t alloc_sz)

{
  void *pvVar1;
  int *in_EAX;
  int iVar2;
  
                    /* Unresolved local var: size_t need_sz@[???]
                       Unresolved local var: char * h@[???] */
  if (in_EAX != (int *)0x0) {
    pvVar1 = (void *)*in_EAX;
    if ((pvVar1 != (void *)0x0) && ((char **)(end + -(int)pvVar1) != p)) {
      iVar2 = realloc(pvVar1,(size_t)(end + -(int)pvVar1));
      if (iVar2 != 0) {
        *in_EAX = iVar2;
      }
    }
    return;
  }
  return;
}



// --- Function: release_ptrs @ 00403070 ---

void __fastcall release_ptrs(gcollect **pt,char **wbuf)

{
  uint *puVar1;
  int iVar2;
  undefined4 *in_EAX;
  uint uVar3;
  uint *puVar4;
  
                    /* Unresolved local var: gcollect * pf@[???]
                       Unresolved local var: size_t cnt@[???] */
  free(*wbuf);
  puVar4 = (uint *)*in_EAX;
  *wbuf = (char *)0x0;
  if (puVar4 != (uint *)0x0) {
    do {
                    /* Unresolved local var: gcollect * pf_sv@[???] */
      uVar3 = 0;
      if (*puVar4 != 0) {
        do {
          free(*(void **)puVar4[uVar3 + 2]);
          iVar2 = uVar3 + 2;
          uVar3 = uVar3 + 1;
          *(undefined4 *)puVar4[iVar2] = 0;
        } while (uVar3 < *puVar4);
      }
      puVar1 = (uint *)puVar4[1];
      free(puVar4);
      puVar4 = puVar1;
    } while (puVar1 != (uint *)0x0);
    *in_EAX = 0;
  }
  return;
}



// --- Function: resize_wbuf @ 004030f0 ---

char * __fastcall resize_wbuf(size_t wpsz,size_t *wbuf_max_sz,char *old)

{
  size_t in_EAX;
  char *pcVar1;
  uint uVar2;
  
                    /* Unresolved local var: char * wbuf@[???]
                       Unresolved local var: size_t nsz@[???] */
  if (*wbuf_max_sz != in_EAX) {
    return (char *)wpsz;
  }
  uVar2 = *wbuf_max_sz * 2;
  if (uVar2 < 0x100) {
    uVar2 = 0x100;
  }
  if (wpsz == 0) {
    pcVar1 = (char *)malloc(uVar2);
    if (pcVar1 == (char *)0x0) {
      return (char *)0x0;
    }
  }
  else {
    pcVar1 = (char *)realloc((void *)wpsz,uVar2);
    if (pcVar1 == (char *)0x0) {
      free((void *)wpsz);
      return (char *)0x0;
    }
  }
  *wbuf_max_sz = uVar2;
  return pcVar1;
}



// --- Function: cleanup_return @ 00403160 ---

int __fastcall cleanup_return(int rval,gcollect **pfree,char **strp,char **wbuf)

{
  gcollect *pgVar1;
  gcollect *pgVar2;
  int in_EAX;
  
  if (in_EAX != -1) {
                    /* Unresolved local var: gcollect * pf@[???]
                       Unresolved local var: gcollect * pf_sv@[???] */
    pgVar2 = *pfree;
    while (pgVar2 != (gcollect *)0x0) {
      pgVar1 = pgVar2->next;
      free(pgVar2);
      pgVar2 = pgVar1;
    }
    *pfree = (gcollect *)0x0;
    if (rval != 0) {
      free(*(void **)rval);
      *(undefined4 *)rval = 0;
    }
    free(*strp);
    *strp = (char *)0x0;
    return in_EAX;
  }
  release_ptrs((gcollect **)rval,strp);
  return -1;
}



// --- Function: in_ch @ 004031f0 ---

int __fastcall in_ch(_IFP *s,size_t *rin)

{
  byte bVar1;
  FILE *pFVar2;
  undefined4 *in_EAX;
  int iVar3;
  
                    /* Unresolved local var: int r@[???] */
  iVar3 = in_EAX[0x402];
  if (iVar3 == 0) {
                    /* Unresolved local var: int r@[???] */
    if ((*(byte *)(in_EAX + 0x403) & 1) == 0) {
                    /* Unresolved local var: char * ps@[???] */
      pFVar2 = (FILE *)*in_EAX;
      if ((*(byte *)(in_EAX + 0x401) & 1) == 0) {
                    /* Unresolved local var: FILE * fp@[???] */
        iVar3 = getc(pFVar2);
        if (iVar3 != -1) {
          *rin = *rin + 1;
          return iVar3;
        }
      }
      else {
        bVar1 = *(byte *)&pFVar2->_ptr;
        if (bVar1 != 0) {
          *rin = *rin + 1;
          *in_EAX = (undefined1 *)((int)&pFVar2->_ptr + 1);
          return (uint)bVar1;
        }
      }
      *(byte *)(in_EAX + 0x403) = *(byte *)(in_EAX + 0x403) | 1;
    }
    iVar3 = -1;
  }
  else {
    in_EAX[0x402] = iVar3 + -1;
    iVar3 = in_EAX[iVar3];
    *rin = *rin + 1;
  }
  return iVar3;
}



// --- Function: back_ch @ 00403280 ---

void __fastcall back_ch(int c,_IFP *s,size_t *rin,int not_eof)

{
  int iVar1;
  int in_EAX;
  
  if ((((uint)rin & 1) == 0) && (in_EAX == -1)) {
    return;
  }
  if ((s->field_0x1004 & 1) != 0) {
    *(int *)c = *(int *)c + -1;
    iVar1 = s->back_top;
    s->bch[iVar1] = in_EAX;
    s->back_top = iVar1 + 1;
    return;
  }
                    /* Unresolved local var: FILE * fp@[???] */
  ungetc(in_EAX,(s->field_0).fp);
  *(int *)c = *(int *)c + -1;
  return;
}



// --- Function: __mingw_sformat @ 004032e0 ---

/* WARNING: Type propagation algorithm not settling */

int __fastcall __mingw_sformat(_IFP *s,char *format,va_list argp)

{
  undefined1 *puVar1;
  double dVar2;
  byte *pbVar3;
  gcollect *pgVar4;
  float fVar5;
  gcollect *pgVar6;
  bool bVar7;
  anon_union_4_2_743ac4ea_for__IFP_0 *paVar8;
  char **ppcVar9;
  byte bVar10;
  char cVar11;
  char cVar12;
  _IFP *in_EAX;
  undefined4 *puVar13;
  int iVar14;
  int iVar15;
  size_t sVar16;
  int *piVar17;
  char *pcVar18;
  undefined4 uVar19;
  size_t sVar20;
  _IFP *s_00;
  _IFP *extraout_ECX;
  _IFP *extraout_ECX_00;
  _IFP *extraout_ECX_01;
  _IFP *extraout_ECX_02;
  _IFP *extraout_ECX_03;
  _IFP *p_Var21;
  _IFP *extraout_ECX_04;
  _IFP *extraout_ECX_05;
  _IFP *extraout_ECX_06;
  _IFP *s_01;
  _IFP *extraout_ECX_07;
  _IFP *s_02;
  _IFP *extraout_ECX_08;
  _IFP *extraout_ECX_09;
  _IFP *extraout_ECX_10;
  _IFP *extraout_ECX_11;
  _IFP *extraout_ECX_12;
  _IFP *extraout_ECX_13;
  _IFP *s_03;
  _IFP *p_Var22;
  _IFP *extraout_ECX_14;
  _IFP *extraout_ECX_15;
  _IFP *extraout_ECX_16;
  _IFP *s_04;
  _IFP *extraout_ECX_17;
  _IFP *extraout_ECX_18;
  _IFP *extraout_ECX_19;
  _IFP *extraout_ECX_20;
  _IFP *extraout_ECX_21;
  _IFP *extraout_ECX_22;
  _IFP *extraout_ECX_23;
  _IFP *extraout_ECX_24;
  _IFP *extraout_ECX_25;
  _IFP *extraout_ECX_26;
  _IFP *extraout_ECX_27;
  _IFP *extraout_ECX_28;
  _IFP *extraout_ECX_29;
  _IFP *extraout_ECX_30;
  _IFP *s_05;
  _IFP *extraout_ECX_31;
  _IFP *extraout_ECX_32;
  _IFP *extraout_ECX_33;
  _IFP *extraout_ECX_34;
  _IFP *extraout_ECX_35;
  _IFP *extraout_ECX_36;
  _IFP *extraout_ECX_37;
  _IFP *extraout_ECX_38;
  _IFP *extraout_ECX_39;
  _IFP *s_06;
  _IFP *s_07;
  _IFP *extraout_ECX_40;
  _IFP *extraout_ECX_41;
  _IFP *extraout_ECX_42;
  _IFP *extraout_ECX_43;
  _IFP *extraout_ECX_44;
  _IFP *extraout_ECX_45;
  _IFP *extraout_ECX_46;
  _IFP *extraout_ECX_47;
  _IFP *extraout_ECX_48;
  _IFP *s_08;
  _IFP *extraout_ECX_49;
  _IFP *extraout_ECX_50;
  _IFP *extraout_ECX_51;
  byte bVar23;
  uint uVar24;
  uint uVar25;
  uintmax_t *puVar26;
  _IFP *p_Var27;
  double *pdVar28;
  float *pfVar29;
  float10 *pfVar30;
  size_t *psVar31;
  undefined2 *puVar32;
  _IFP *p_Var33;
  _IFP *p_Var34;
  _IFP *p_Var35;
  byte *pbVar36;
  byte *pbVar37;
  char *pcVar38;
  int iVar39;
  undefined *puVar40;
  _IFP *s_09;
  bool bVar41;
  float10 extraout_ST0;
  float10 extraout_ST0_00;
  float10 fVar42;
  uintmax_t uVar43;
  float fVar44;
  _IFP *in_stack_ffffff44;
  _IFP *in_stack_ffffff48;
  _IFP *local_ac;
  _IFP *local_9c;
  char **local_98;
  _IFP *local_94;
  int local_90;
  _IFP *local_88;
  _IFP *local_84;
  _IFP *local_80;
  _IFP *local_7c;
  _IFP *local_78;
  _IFP *local_74;
  _IFP *local_70;
  char *local_68;
  _IFP *local_64;
  gcollect *gcollect;
  size_t read_in;
  size_t wbuf_max_sz;
  char *wbuf;
  char *tmp_wbuf_ptr;
  char buf [5];
  mbstate_t state;
  mbstate_t cstate;
  
                    /* Unresolved local var: char * f@[DW_OP_reg2(EDX)]
                       Unresolved local var: size_t cnt@[???]
                       Unresolved local var: ssize_t str_sz@[???]
                       Unresolved local var: char * str@[???]
                       Unresolved local var: char * * pstr@[???]
                       Unresolved local var: wchar_t * wstr@[???]
                       Unresolved local var: int rval@[???]
                       Unresolved local var: int c@[???]
                       Unresolved local var: int ignore_ws@[???]
                       Unresolved local var: va_list arg@[???]
                       Unresolved local var: uchar fc@[???]
                       Unresolved local var: uint npos@[???]
                       Unresolved local var: int width@[???]
                       Unresolved local var: int flags@[???]
                       Unresolved local var: int base@[???]
                       Unresolved local var: int errno_sv@[???]
                       Unresolved local var: size_t wbuf_cur_sz@[???]
                       Unresolved local var: size_t read_in_sv@[???]
                       Unresolved local var: size_t new_sz@[???]
                       Unresolved local var: size_t n@[???]
                       Unresolved local var: char seen_dot@[???]
                       Unresolved local var: char seen_exp@[???]
                       Unresolved local var: char is_neg@[???]
                       Unresolved local var: char not_in@[???]
                       Unresolved local var: char * lc_decimal_point@[???]
                       Unresolved local var: char * lc_thousands_sep@[???]
                       Unresolved local var: anon_union_8_4_87643653 cv_val@[???] */
  gcollect = (gcollect *)0x0;
  read_in = 0;
  wbuf_max_sz = 0;
  wbuf = (char *)0x0;
  if ((in_EAX->field_0).fp == (void *)0x0 || format == (char *)0x0) {
    piVar17 = __errno();
    *piVar17 = 0x16;
    return -1;
  }
  state._Wchar = 0;
  state._Byte = L'\0';
  state._State = L'\0';
  puVar13 = (undefined4 *)localeconv();
  pbVar3 = (byte *)*puVar13;
  iVar14 = localeconv();
  p_Var21 = *(_IFP **)(iVar14 + 4);
  local_9c = p_Var21;
  if ((p_Var21 != (_IFP *)0x0) && (local_9c = (_IFP *)0x0, *(char *)&p_Var21->field_0 != '\0')) {
    local_9c = p_Var21;
  }
  cVar11 = *format;
  if (cVar11 == '\0') {
    local_90 = 0;
    pcVar38 = (char *)0x0;
    goto LAB_00403581;
  }
  local_84 = (_IFP *)0x0;
  p_Var33 = (_IFP *)0x0;
  local_90 = 0;
  local_7c = (_IFP *)0x0;
  local_98 = (char **)0x0;
  local_70 = (_IFP *)0x0;
  local_78 = (_IFP *)0x0;
  s_09 = (_IFP *)0x0;
  local_ac = (_IFP *)format;
  local_80 = s;
LAB_004033bb:
  if (cVar11 < '\0') {
                    /* Unresolved local var: int len@[???] */
    in_stack_ffffff48 = (_IFP *)strlen((char *)local_ac);
    in_stack_ffffff44 = local_ac;
    sVar16 = mbrlen((char *)local_ac,(size_t)in_stack_ffffff48,(mbstate_t *)&state);
    p_Var21 = extraout_ECX_02;
    if (0 < (int)sVar16) {
      piVar17 = local_ac->bch;
      while ((s_09 = (_IFP *)in_ch(p_Var21,&read_in), s_09 != (_IFP *)0xffffffff &&
             (paVar8 = &local_ac->field_0, local_ac = (_IFP *)((int)&local_ac->field_0 + 1),
             s_09 == (_IFP *)(uint)*(byte *)paVar8))) {
        p_Var21 = extraout_ECX_03;
        if (local_ac == (_IFP *)((int)piVar17 + (sVar16 - 4))) goto LAB_004034c4;
      }
                    /* Unresolved local var: FILE * fp@[???] */
      sVar16 = read_in - 1;
      if ((in_EAX->field_0x1004 & 1) == 0) {
        ungetc((int)s_09,(in_EAX->field_0).fp);
        p_Var21 = extraout_ECX_35;
      }
      else {
        iVar14 = in_EAX->back_top;
        in_EAX->bch[iVar14] = (int)s_09;
        in_EAX->back_top = iVar14 + 1;
        p_Var21 = in_EAX;
      }
      read_in = sVar16;
      pgVar6 = gcollect;
      if (local_90 == 0) goto LAB_00404040;
      while (pgVar6 != (gcollect *)0x0) {
        pgVar4 = pgVar6->next;
        free(pgVar6);
        pgVar6 = pgVar4;
      }
      goto LAB_00403471;
    }
  }
  p_Var34 = (_IFP *)(uint)*(byte *)&local_ac->field_0;
  p_Var27 = (_IFP *)((int)&local_ac->field_0 + 1);
  if (*(byte *)&local_ac->field_0 == 0x25) {
    local_74 = (_IFP *)0x0;
    bVar23 = *(byte *)((int)&local_ac->field_0 + 1);
    uVar24 = (uint)bVar23;
    if (uVar24 - 0x30 < 10) {
                    /* Unresolved local var: char * svf@[???] */
      local_74 = (_IFP *)((char)bVar23 + -0x30);
      p_Var21 = (_IFP *)((int)&local_ac->field_0 + 2);
      bVar23 = *(byte *)((int)&local_ac->field_0 + 2);
      while (bVar23 - 0x30 < 10) {
        p_Var21 = (_IFP *)((int)&p_Var21->field_0 + 1);
        local_74 = (_IFP *)((bVar23 - 0x30) + (int)local_74 * 10);
        bVar23 = *(byte *)&p_Var21->field_0;
      }
      if (bVar23 == 0x24) {
        uVar24 = (uint)*(byte *)((int)&p_Var21->field_0 + 1);
        p_Var27 = (_IFP *)((int)&p_Var21->field_0 + 1);
      }
      else {
        local_74 = (_IFP *)0x0;
      }
    }
    local_94 = (_IFP *)0x0;
    do {
      cVar11 = (char)uVar24;
      if (cVar11 == '*') {
        uVar24 = (uint)*(byte *)((int)&p_Var27->field_0 + 1);
        local_94 = (_IFP *)((uint)local_94 | 0x80);
      }
      else if (cVar11 == '\'') {
        uVar24 = (uint)*(byte *)((int)&p_Var27->field_0 + 1);
        p_Var21 = (_IFP *)((uint)local_94 | 0x100);
        if (local_9c != (_IFP *)0x0) {
          local_94 = p_Var21;
        }
      }
      else {
        if (cVar11 != 'I') goto LAB_0040369c;
        bVar23 = *(byte *)((int)&p_Var27->field_0 + 1);
        uVar24 = (uint)bVar23;
        if (bVar23 == 0x36) {
          if (*(char *)((int)&p_Var27->field_0 + 2) != '4') goto LAB_00403692;
          uVar24 = (uint)*(byte *)((int)&p_Var27->field_0 + 3);
          local_94 = (_IFP *)((uint)local_94 | 0xc);
          p_Var27 = (_IFP *)((int)&p_Var27->field_0 + 2);
        }
        else if (bVar23 == 0x33) {
          if (*(char *)((int)&p_Var27->field_0 + 2) != '2') goto LAB_00403692;
          uVar24 = (uint)*(byte *)((int)&p_Var27->field_0 + 3);
          local_94 = (_IFP *)((uint)local_94 | 4);
          p_Var27 = (_IFP *)((int)&p_Var27->field_0 + 2);
        }
        else {
          local_94 = (_IFP *)((uint)local_94 | 4);
        }
      }
      p_Var27 = (_IFP *)((int)&p_Var27->field_0 + 1);
    } while( true );
  }
  in_stack_ffffff44 = p_Var34;
  iVar14 = isspace((int)p_Var34);
  local_ac = p_Var27;
  if (iVar14 == 0) {
    s_09 = (_IFP *)in_ch(s_00,&read_in);
    if (s_09 != (_IFP *)0xffffffff) {
      p_Var21 = extraout_ECX;
      if (p_Var33 != (_IFP *)0x0) {
        in_stack_ffffff44 = s_09;
        iVar14 = isspace((int)s_09);
        p_Var21 = extraout_ECX_00;
        while( true ) {
          if (iVar14 == 0) goto LAB_00403416;
          s_09 = (_IFP *)in_ch(p_Var21,&read_in);
          if (s_09 == (_IFP *)0xffffffff) break;
          in_stack_ffffff44 = s_09;
          iVar14 = isspace((int)s_09);
          p_Var21 = extraout_ECX_04;
        }
        p_Var21 = extraout_ECX_05;
        pgVar6 = gcollect;
        if (local_90 == 0) goto LAB_00404040;
        while (pgVar6 != (gcollect *)0x0) {
          pgVar4 = pgVar6->next;
          free(pgVar6);
          pgVar6 = pgVar4;
        }
        goto LAB_00403471;
      }
LAB_00403416:
      if (p_Var34 != s_09) {
                    /* Unresolved local var: FILE * fp@[???] */
        sVar16 = read_in - 1;
        if ((in_EAX->field_0x1004 & 1) == 0) {
          ungetc((int)s_09,(in_EAX->field_0).fp);
          read_in = sVar16;
          pgVar6 = gcollect;
        }
        else {
          iVar14 = in_EAX->back_top;
          in_EAX->bch[iVar14] = (int)s_09;
          in_EAX->back_top = iVar14 + 1;
          read_in = sVar16;
          pgVar6 = gcollect;
        }
        while (pgVar6 != (gcollect *)0x0) {
          pgVar4 = pgVar6->next;
          free(pgVar6);
          pgVar6 = pgVar4;
        }
        goto LAB_00403471;
      }
      p_Var33 = (_IFP *)0x0;
      goto LAB_004034c4;
    }
    p_Var21 = extraout_ECX;
    pgVar6 = gcollect;
    if (local_90 == 0) goto LAB_00404040;
    while (pgVar6 != (gcollect *)0x0) {
      pgVar4 = pgVar6->next;
      free(pgVar6);
      pgVar6 = pgVar4;
    }
    goto LAB_00403471;
  }
  p_Var33 = (_IFP *)0x1;
  p_Var21 = s_00;
  goto LAB_004034c4;
LAB_00403692:
  local_94 = (_IFP *)((uint)local_94 | 4);
  p_Var27 = (_IFP *)((int)&p_Var27->field_0 + 1);
LAB_0040369c:
  p_Var34 = (_IFP *)0x0;
  if (uVar24 - 0x30 < 10) {
    do {
      p_Var27 = (_IFP *)((int)&p_Var27->field_0 + 1);
      p_Var34 = (_IFP *)((int)(char)((char)uVar24 + -0x30) + (int)p_Var34 * 10);
      uVar24 = (uint)*(byte *)&p_Var27->field_0;
    } while (uVar24 - 0x30 < 10);
    if (p_Var34 == (_IFP *)0x0) {
      p_Var34 = (_IFP *)0xffffffff;
    }
  }
  else {
    p_Var34 = (_IFP *)0xffffffff;
  }
  pgVar6 = gcollect;
  if ((char)uVar24 == '\0') goto joined_r0x00404856;
  switch(uVar24 - 0x4c & 0xff) {
  case 0:
  case 0x25:
    local_88 = (_IFP *)((int)&p_Var27->field_0 + 1);
    local_94 = (_IFP *)((uint)local_94 | 0xc);
    uVar24 = (uint)*(byte *)((int)&p_Var27->field_0 + 1);
    break;
  default:
switchD_004036e8_caseD_1:
    uVar24 = (uint)*(byte *)&p_Var27->field_0;
    local_88 = p_Var27;
    break;
  case 0x15:
    bVar23 = *(byte *)((int)&p_Var27->field_0 + 1);
    uVar24 = (uint)bVar23;
    if (((bVar23 & 0xf7) != 0x53) && (bVar23 != 0x73)) goto switchD_004036e8_caseD_1;
    local_88 = (_IFP *)((int)&p_Var27->field_0 + 1);
    local_94 = (_IFP *)((uint)local_94 | 0x200);
    goto LAB_00403758;
  case 0x1c:
    bVar23 = *(byte *)((int)&p_Var27->field_0 + 1);
    uVar24 = (uint)bVar23;
    if (bVar23 == 0x68) {
      local_88 = (_IFP *)((int)&p_Var27->field_0 + 2);
      local_94 = (_IFP *)((uint)local_94 | 1);
      uVar24 = (uint)*(byte *)((int)&p_Var27->field_0 + 2);
    }
    else {
      local_88 = (_IFP *)((int)&p_Var27->field_0 + 1);
      local_94 = (_IFP *)((uint)local_94 | 2);
    }
    break;
  case 0x1e:
    local_88 = (_IFP *)((int)&p_Var27->field_0 + 1);
    local_94 = (_IFP *)((uint)local_94 | 8);
    uVar24 = (uint)*(byte *)((int)&p_Var27->field_0 + 1);
    break;
  case 0x20:
    bVar23 = *(byte *)((int)&p_Var27->field_0 + 1);
    uVar24 = (uint)bVar23;
    if (bVar23 == 0x6c) {
      local_88 = (_IFP *)((int)&p_Var27->field_0 + 2);
      local_94 = (_IFP *)((uint)local_94 | 0xc);
      uVar24 = (uint)*(byte *)((int)&p_Var27->field_0 + 2);
    }
    else {
      local_88 = (_IFP *)((int)&p_Var27->field_0 + 1);
      local_94 = (_IFP *)((uint)local_94 | 4);
    }
    break;
  case 0x21:
    bVar23 = *(byte *)((int)&p_Var27->field_0 + 1);
    uVar24 = (uint)bVar23;
    if (bVar23 == 0x6c) {
      local_88 = (_IFP *)((int)&p_Var27->field_0 + 2);
      local_94 = (_IFP *)((uint)local_94 | 0x404);
      uVar24 = (uint)*(byte *)((int)&p_Var27->field_0 + 2);
    }
    else {
      local_88 = (_IFP *)((int)&p_Var27->field_0 + 1);
      local_94 = (_IFP *)((uint)local_94 | 0x400);
    }
    break;
  case 0x28:
  case 0x2e:
    local_88 = (_IFP *)((int)&p_Var27->field_0 + 1);
    local_94 = (_IFP *)((uint)local_94 | 4);
    uVar24 = (uint)*(byte *)((int)&p_Var27->field_0 + 1);
  }
  if ((char)uVar24 == '\0') goto joined_r0x0040540e;
LAB_00403758:
  local_ac = (_IFP *)((int)&local_88->field_0 + 1);
  bVar23 = (byte)uVar24;
  if (p_Var33 != (_IFP *)0x0) {
LAB_00403f58:
    piVar17 = __errno();
    iVar14 = *piVar17;
    piVar17 = __errno();
    *piVar17 = 0;
    p_Var21 = extraout_ECX_11;
LAB_00403fa2:
    if ((s_09 == (_IFP *)0xffffffff) ||
       (s_09 = (_IFP *)in_ch(p_Var21,&read_in), s_09 == (_IFP *)0xffffffff)) {
      piVar17 = __errno();
      if (*piVar17 == 4) {
        p_Var21 = extraout_ECX_13;
        pgVar6 = gcollect;
        if (local_90 == 0) goto LAB_00404040;
        while (pgVar6 != (gcollect *)0x0) {
          pgVar4 = pgVar6->next;
          free(pgVar6);
          pgVar6 = pgVar4;
        }
        goto LAB_00403471;
      }
      s_09 = (_IFP *)0xffffffff;
    }
    in_stack_ffffff44 = s_09;
    iVar15 = isspace((int)s_09);
    p_Var21 = extraout_ECX_12;
    if (iVar15 == 0) goto LAB_004038b6;
    goto LAB_00403fa2;
  }
  if (((bVar23 & 0xdf) == 0x43) || (bVar23 == 0x5b)) goto LAB_00403910;
  p_Var21 = (_IFP *)0x5;
  if (bVar23 != 0x6e) goto LAB_00403f58;
LAB_00403793:
  bVar10 = (byte)p_Var21;
  if ((1 << (bVar10 & 0x1f) & 0x90c1U) == 0) {
    if (bVar10 != 10) {
      if (bVar10 != 5) goto switchD_00403942_caseD_26;
      p_Var33 = (_IFP *)((uint)local_94 & 0x80);
      p_Var21 = local_94;
      if (((uint)local_94 & 0x80) == 0) {
        if (((uint)local_94 & 8) == 0) {
          p_Var33 = (_IFP *)((uint)local_94 & 4);
          if (((uint)local_94 & 4) == 0) {
            if (((uint)local_94 & 2) == 0) {
              p_Var33 = (_IFP *)((uint)local_94 & 1);
              if (((uint)local_94 & 1) == 0) {
                if (local_74 == (_IFP *)0x0) {
                  paVar8 = &local_80->field_0;
                  local_80 = (_IFP *)local_80->bch;
                  *(size_t *)paVar8->fp = read_in;
                  p_Var21 = local_80;
                }
                else {
                    /* Unresolved local var: va_list ap@[???] */
                  p_Var21 = s;
                  if ((_IFP *)((int)local_74 + -1) != (_IFP *)0x0) {
                    p_Var21 = (_IFP *)(s->bch + (int)local_74 + -2);
                  }
                  *(size_t *)(p_Var21->field_0).fp = read_in;
                  p_Var21 = (_IFP *)((int)local_74 + -1);
                }
              }
              else {
                if (local_74 == (_IFP *)0x0) {
                  pcVar18 = (local_80->field_0).str;
                  p_Var21 = (_IFP *)local_80->bch;
                  local_80 = p_Var21;
                }
                else {
                    /* Unresolved local var: va_list ap@[???] */
                  p_Var21 = (_IFP *)((int)local_74 + -1);
                  p_Var33 = s;
                  if (p_Var21 != (_IFP *)0x0) {
                    p_Var33 = (_IFP *)(s->bch + (int)local_74 + -2);
                  }
                  pcVar18 = (p_Var33->field_0).str;
                }
                *pcVar18 = (char)read_in;
                p_Var33 = (_IFP *)0x0;
              }
            }
            else {
              if (local_74 == (_IFP *)0x0) {
                puVar32 = (local_80->field_0).fp;
                p_Var21 = (_IFP *)local_80->bch;
                local_80 = p_Var21;
              }
              else {
                    /* Unresolved local var: va_list ap@[???] */
                p_Var21 = (_IFP *)((int)local_74 + -1);
                p_Var27 = s;
                if (p_Var21 != (_IFP *)0x0) {
                  p_Var27 = (_IFP *)(s->bch + (int)local_74 + -2);
                }
                puVar32 = (p_Var27->field_0).fp;
              }
              *puVar32 = (short)read_in;
            }
          }
          else {
            if (local_74 == (_IFP *)0x0) {
              psVar31 = (local_80->field_0).fp;
              p_Var21 = (_IFP *)local_80->bch;
              local_80 = p_Var21;
            }
            else {
                    /* Unresolved local var: va_list ap@[???] */
              p_Var21 = (_IFP *)((int)local_74 + -1);
              p_Var33 = s;
              if (p_Var21 != (_IFP *)0x0) {
                p_Var33 = (_IFP *)(s->bch + (int)local_74 + -2);
              }
              psVar31 = (p_Var33->field_0).fp;
            }
            *psVar31 = read_in;
            p_Var33 = (_IFP *)0x0;
          }
        }
        else {
          if (local_74 == (_IFP *)0x0) {
            psVar31 = (local_80->field_0).fp;
            p_Var21 = (_IFP *)local_80->bch;
            local_80 = p_Var21;
          }
          else {
                    /* Unresolved local var: va_list ap@[???] */
            p_Var21 = (_IFP *)((int)local_74 + -1);
            p_Var27 = (_IFP *)(s->bch + (int)local_74 + -2);
            if (p_Var21 == (_IFP *)0x0) {
              p_Var27 = s;
            }
            psVar31 = (p_Var27->field_0).fp;
          }
          *psVar31 = read_in;
          psVar31[1] = 0;
        }
        goto LAB_004034c4;
      }
      goto LAB_00404562;
    }
LAB_00403c9b:
    if (((uint)local_94 & 0x80) == 0) {
      if (((uint)local_94 & 0x600) == 0) {
        if (local_74 == (_IFP *)0x0) {
          local_70 = (local_80->field_0).fp;
          local_80 = (_IFP *)local_80->bch;
        }
        else {
                    /* Unresolved local var: va_list ap@[???] */
          p_Var21 = (_IFP *)(s->bch + (int)local_74 + -2);
          if (local_74 == (_IFP *)0x1) {
            p_Var21 = s;
          }
          local_70 = (p_Var21->field_0).fp;
        }
        p_Var21 = local_70;
        if (local_70 == (_IFP *)0x0) goto LAB_00404092;
      }
      else {
        if (local_74 == (_IFP *)0x0) {
          local_98 = (local_80->field_0).fp;
          local_80 = (_IFP *)local_80->bch;
        }
        else {
                    /* Unresolved local var: va_list ap@[???] */
          p_Var21 = (_IFP *)(s->bch + (int)local_74 + -2);
          if (local_74 == (_IFP *)0x1) {
            p_Var21 = s;
          }
          local_98 = (p_Var21->field_0).fp;
        }
        if (local_98 == (char **)0x0) {
LAB_00405af1:
          iVar14 = cleanup_return(0,&gcollect,&wbuf,(char **)in_stack_ffffff48);
          return iVar14;
        }
        local_70 = (_IFP *)malloc(100);
        pgVar6 = gcollect;
        *local_98 = (char *)local_70;
        if (local_70 == (_IFP *)0x0) goto LAB_00404e56;
                    /* Unresolved local var: gcollect * np@[???] */
        if (gcollect == (gcollect *)0x0) {
LAB_00403d15:
          gcollect = (gcollect *)malloc(0x88);
          p_Var21 = (_IFP *)0x1;
          uVar24 = 0;
          gcollect->count = 0;
          gcollect->next = pgVar6;
        }
        else {
          uVar24 = gcollect->count;
          p_Var21 = (_IFP *)(uVar24 + 1);
          if (0x1f < uVar24) goto LAB_00403d15;
        }
        gcollect->count = (size_t)p_Var21;
        gcollect->ptrs[uVar24] = local_98;
        local_78 = (_IFP *)0x64;
      }
    }
    s_09 = (_IFP *)in_ch(p_Var21,&read_in);
    if (s_09 == (_IFP *)0xffffffff) {
LAB_00404e56:
      iVar14 = cleanup_return((int)local_98,&gcollect,&wbuf,(char **)in_stack_ffffff48);
      return iVar14;
    }
    while (in_stack_ffffff44 = s_09, iVar14 = isspace((int)s_09), iVar14 == 0) {
      p_Var21 = extraout_ECX_09;
      if (((uint)local_94 & 0x80) == 0) {
        *(char *)&local_70->field_0 = (char)s_09;
        local_70 = (_IFP *)((int)&local_70->field_0 + 1);
        if (((uint)local_94 & 0x600) != 0) {
          p_Var33 = (_IFP *)*local_98;
          p_Var21 = (_IFP *)((int)local_78->bch + (int)(p_Var33->bch + -2));
          if (local_70 == p_Var21) {
            p_Var21 = (_IFP *)((int)local_78 * 2);
            while (in_stack_ffffff48 = p_Var21, pcVar18 = (char *)realloc(p_Var33,(size_t)p_Var21),
                  pcVar18 == (char *)0x0) {
              p_Var27 = (_IFP *)((int)&(local_78->field_0).fp + 1);
              if (p_Var21 <= p_Var27) {
LAB_004061c8:
                if (((uint)local_94 & 0x400) == 0) {
                  *(char *)((int)local_78->bch + (int)(*local_98 + -5)) = '\0';
                  local_98 = (char **)0x0;
                }
LAB_004061f1:
                iVar14 = cleanup_return((int)local_98,&gcollect,&wbuf,(char **)in_stack_ffffff48);
                return iVar14;
              }
              p_Var33 = (_IFP *)*local_98;
              p_Var21 = p_Var27;
            }
            *local_98 = pcVar18;
            local_70 = (_IFP *)((int)local_78->bch + (int)(pcVar18 + -4));
            in_stack_ffffff44 = p_Var33;
            local_78 = p_Var21;
          }
        }
      }
      if (((0 < (int)p_Var34) &&
          (p_Var34 = (_IFP *)&p_Var34[-1].field_0x100f, p_Var34 == (_IFP *)0x0)) ||
         (s_09 = (_IFP *)in_ch(p_Var21,&read_in), p_Var21 = extraout_ECX_08,
         s_09 == (_IFP *)0xffffffff)) goto LAB_00404c17;
    }
                    /* Unresolved local var: FILE * fp@[???] */
    sVar16 = read_in - 1;
    if ((in_EAX->field_0x1004 & 1) == 0) {
      in_stack_ffffff48 = (in_EAX->field_0).fp;
      in_stack_ffffff44 = s_09;
      ungetc((int)s_09,(FILE *)in_stack_ffffff48);
      p_Var21 = extraout_ECX_49;
      read_in = sVar16;
    }
    else {
      iVar14 = in_EAX->back_top;
      in_EAX->bch[iVar14] = (int)s_09;
      in_EAX->back_top = iVar14 + 1;
      p_Var21 = in_EAX;
      read_in = sVar16;
    }
LAB_00404c17:
    if (((uint)local_94 & 0x80) == 0) {
                    /* Unresolved local var: size_t need_sz@[???]
                       Unresolved local var: char * h@[???] */
      *(char *)&local_70->field_0 = '\0';
      local_70 = (_IFP *)((int)&local_70->field_0 + 1);
      if (((local_98 != (char **)0x0) && (p_Var33 = (_IFP *)*local_98, p_Var33 != (_IFP *)0x0)) &&
         ((p_Var27 = (_IFP *)((int)local_70 - (int)p_Var33), local_78 != p_Var27 &&
          (pcVar18 = (char *)realloc(p_Var33,(size_t)p_Var27), p_Var21 = extraout_ECX_24,
          in_stack_ffffff44 = p_Var33, in_stack_ffffff48 = p_Var27, pcVar18 != (char *)0x0)))) {
        *local_98 = pcVar18;
      }
      local_90 = local_90 + 1;
      local_98 = (char **)0x0;
      p_Var33 = (_IFP *)0x0;
      goto LAB_004034c4;
    }
  }
  else {
switchD_00403942_caseD_58:
    switch(bVar23) {
    case 0x58:
    case 0x78:
      local_84 = (_IFP *)0x10;
      break;
    case 100:
      local_94 = (_IFP *)((uint)local_94 | 0x10);
      local_84 = (_IFP *)0xa;
      break;
    case 0x69:
      local_94 = (_IFP *)((uint)local_94 | 0x10);
      local_84 = (_IFP *)0x0;
      break;
    case 0x6f:
      local_84 = (_IFP *)0x8;
      break;
    case 0x70:
      local_84 = (_IFP *)0x10;
      local_94 = (_IFP *)((uint)local_94 & 0xfffffff1 | 0x24);
      break;
    case 0x75:
      local_84 = (_IFP *)0xa;
    }
    s_09 = (_IFP *)in_ch(p_Var21,&read_in);
    if (s_09 == (_IFP *)0xffffffff) goto LAB_00404e56;
    iVar14 = 0;
    if (((uint)((int)s_09[-1].bch + 0xfe1U) & 0xfffffffd) == 0) {
      wbuf = resize_wbuf((size_t)wbuf,&wbuf_max_sz,(char *)in_stack_ffffff44);
      *wbuf = (char)s_09;
      p_Var21 = (_IFP *)0x0;
      if (-1 < (int)p_Var34) {
        p_Var21 = p_Var34;
      }
      p_Var34 = (_IFP *)&p_Var21[-1].field_0x100f;
      s_09 = (_IFP *)in_ch(s_09,&read_in);
      iVar14 = 1;
    }
    if ((s_09 != (_IFP *)0x30) || (p_Var34 == (_IFP *)0x0)) {
      p_Var21 = (_IFP *)0xa;
      if (local_84 != (_IFP *)0x0) {
        p_Var21 = local_84;
      }
      if ((s_09 == (_IFP *)0xffffffff) ||
         (p_Var33 = local_84, local_84 = p_Var21, iVar15 = iVar14, p_Var34 == (_IFP *)0x0)) {
        local_84 = p_Var21;
        if (iVar14 == 0) goto LAB_00405160;
        goto LAB_00404472;
      }
LAB_004050c7:
                    /* Unresolved local var: char * p@[???]
                       Unresolved local var: int remain@[???] */
      while (local_84 == (_IFP *)0x10) {
        in_stack_ffffff44 = s_09;
        iVar14 = isxdigit((int)s_09);
        if (iVar14 == 0) goto LAB_00405154;
LAB_004050f5:
        iVar14 = iVar15;
        iVar15 = iVar15 + 1;
LAB_00405102:
        wbuf = resize_wbuf((size_t)wbuf,&wbuf_max_sz,(char *)in_stack_ffffff44);
        wbuf[iVar14] = (char)s_09;
        p_Var34 = (_IFP *)((int)p_Var34 - (uint)(0 < (int)p_Var34));
        s_09 = (_IFP *)in_ch(s_05,&read_in);
        if ((s_09 == (_IFP *)0xffffffff) || (p_Var33 = extraout_ECX_31, p_Var34 == (_IFP *)0x0))
        goto LAB_00405154;
      }
      if (s_09[-1].bch + 0x3f7 < (int *)0xa) {
        if ((int)((int)s_09[-1].bch + 0xfdd) <= (int)local_84) goto LAB_004050f5;
      }
      else if ((local_84 == (_IFP *)0xa) && (((uint)local_94 & 0x100) != 0)) {
        p_Var21 = (_IFP *)0x7fffffff;
        if (0 < (int)p_Var34) {
          p_Var21 = p_Var34;
        }
        bVar23 = *(byte *)&local_9c->field_0;
        p_Var27 = local_9c;
        p_Var35 = local_9c;
        if ((_IFP *)(uint)bVar23 == s_09) {
          do {
            p_Var27 = (_IFP *)((int)&p_Var35->field_0 + 1);
            if (*(char *)&p_Var27->field_0 == '\0') goto LAB_00405204;
            if (p_Var21 == (_IFP *)0x0) goto LAB_00405229;
            s_09 = (_IFP *)in_ch(p_Var33,&read_in);
            if (s_09 == (_IFP *)0xffffffff) {
              bVar23 = *(byte *)((int)&p_Var35->field_0 + 1);
              break;
            }
            bVar23 = *(byte *)&p_Var27->field_0;
            p_Var21 = (_IFP *)&p_Var21[-1].field_0x100f;
            p_Var33 = extraout_ECX_33;
            p_Var35 = p_Var27;
          } while (s_09 == (_IFP *)(uint)bVar23);
        }
        if (bVar23 == 0) {
LAB_00405204:
          if (0 < (int)p_Var34) {
            p_Var34 = p_Var21;
          }
          iVar14 = iVar15 + -1;
          goto LAB_00405102;
        }
LAB_00405229:
        if (local_9c < p_Var27) {
          pbVar36 = &p_Var27[-1].field_0x100f;
          in_stack_ffffff44 = (_IFP *)0x0;
          back_ch((int)&read_in,in_EAX,(size_t *)0x0,(int)in_stack_ffffff48);
          pbVar37 = pbVar36;
          if (local_9c < pbVar36) {
            do {
                    /* Unresolved local var: FILE * fp@[???] */
              p_Var21 = (_IFP *)(uint)*pbVar37;
              sVar16 = read_in - 1;
              if ((in_EAX->field_0x1004 & 1) == 0) {
                in_stack_ffffff48 = (in_EAX->field_0).fp;
                ungetc((int)p_Var21,(FILE *)in_stack_ffffff48);
                in_stack_ffffff44 = p_Var21;
              }
              else {
                iVar14 = in_EAX->back_top;
                in_EAX->bch[iVar14] = (int)p_Var21;
                in_EAX->back_top = iVar14 + 1;
              }
              pbVar37 = pbVar37 + -1;
              read_in = sVar16;
            } while ((_IFP *)pbVar37 != local_9c);
            pbVar36 = pbVar36 + (int)local_9c + (1 - (int)p_Var27);
          }
          s_09 = (_IFP *)(uint)*pbVar36;
          if (iVar15 == 0) goto LAB_00405160;
          if ((iVar15 == 1) && ((*wbuf - 0x2bU & 0xfd) == 0)) goto LAB_00405177;
          goto LAB_00404494;
        }
      }
LAB_00405154:
      if (iVar15 != 0) goto LAB_0040446b;
LAB_00405160:
                    /* Unresolved local var: int ch@[???] */
      if ((((uint)local_94 & 0x20) == 0) || (cVar11 = tolower((int)s_09), cVar11 != '('))
      goto LAB_00405177;
      cVar11 = 'n';
      puVar40 = &DAT_004113d9;
      p_Var21 = extraout_ECX_32;
      do {
        s_09 = (_IFP *)in_ch(p_Var21,&read_in);
        if ((s_09 == (_IFP *)0xffffffff) ||
           (in_stack_ffffff44 = s_09, cVar12 = tolower((int)s_09), cVar11 != cVar12))
        goto LAB_00405177;
        cVar11 = puVar40[1];
        puVar40 = puVar40 + 1;
        p_Var21 = extraout_ECX_40;
      } while (cVar11 != '\0');
      pcVar18 = resize_wbuf((size_t)wbuf,&wbuf_max_sz,(char *)in_stack_ffffff44);
      iVar15 = 1;
      *pcVar18 = '0';
    }
    else {
      iVar15 = iVar14 + 1;
      if ((int)p_Var34 < 1) {
        p_Var34 = (_IFP *)0xffffffff;
        wbuf = resize_wbuf((size_t)wbuf,&wbuf_max_sz,(char *)in_stack_ffffff44);
        wbuf[iVar14] = '0';
        s_09 = (_IFP *)in_ch(s_06,&read_in);
LAB_00405669:
        in_stack_ffffff44 = s_09;
        iVar14 = tolower((int)s_09);
        p_Var33 = s_07;
        if (iVar14 == 0x78) {
          if (((uint)local_84 & 0xffffffef) == 0) {
            p_Var21 = (_IFP *)0x0;
            if (-1 < (int)p_Var34) {
              p_Var21 = p_Var34;
            }
            p_Var34 = (_IFP *)&p_Var21[-1].field_0x100f;
            s_09 = (_IFP *)in_ch(s_07,&read_in);
            local_84 = (_IFP *)0x10;
            p_Var33 = extraout_ECX_47;
          }
        }
        else if (local_84 == (_IFP *)0x0) {
          local_84 = (_IFP *)0x8;
        }
        if ((p_Var34 != (_IFP *)0x0) && (s_09 != (_IFP *)0xffffffff)) goto LAB_004050c7;
      }
      else {
        p_Var34 = (_IFP *)&p_Var34[-1].field_0x100f;
        wbuf = resize_wbuf((size_t)wbuf,&wbuf_max_sz,(char *)in_stack_ffffff44);
        wbuf[iVar14] = '0';
        s_09 = (_IFP *)in_ch(s_04,&read_in);
        if (p_Var34 != (_IFP *)0x0) goto LAB_00405669;
        if (local_84 == (_IFP *)0x0) {
          local_84 = (_IFP *)0x8;
        }
      }
LAB_0040446b:
      if (iVar15 == 1) {
LAB_00404472:
        if ((*wbuf - 0x2bU & 0xfd) == 0) {
LAB_00405177:
          back_ch((int)&read_in,in_EAX,(size_t *)0x0,(int)in_stack_ffffff48);
          goto LAB_00404092;
        }
        iVar15 = 1;
      }
      pcVar18 = wbuf;
      if (s_09 != (_IFP *)0xffffffff) {
LAB_00404494:
                    /* Unresolved local var: FILE * fp@[???] */
        sVar16 = read_in - 1;
        if ((in_EAX->field_0x1004 & 1) == 0) {
          in_stack_ffffff44 = s_09;
          ungetc((int)s_09,(in_EAX->field_0).fp);
          pcVar18 = wbuf;
          read_in = sVar16;
        }
        else {
          iVar14 = in_EAX->back_top;
          in_EAX->bch[iVar14] = (int)s_09;
          in_EAX->back_top = iVar14 + 1;
          pcVar18 = wbuf;
          read_in = sVar16;
        }
      }
    }
    p_Var21 = (_IFP *)resize_wbuf((size_t)pcVar18,&wbuf_max_sz,(char *)in_stack_ffffff44);
    *(undefined1 *)((int)p_Var21->bch + iVar15 + -4) = 0;
    p_Var33 = (_IFP *)((uint)local_94 & 0x10);
    in_stack_ffffff44 = p_Var21;
    wbuf = (char *)p_Var21;
    if (((uint)local_94 & 8) == 0) {
      in_stack_ffffff48 = (_IFP *)&tmp_wbuf_ptr;
      if (p_Var33 == (_IFP *)0x0) {
        uVar19 = strtoul((char *)p_Var21,(char **)in_stack_ffffff48,(int)local_84);
        if (p_Var21 == (_IFP *)tmp_wbuf_ptr) goto LAB_00404092;
        p_Var21 = extraout_ECX_36;
        if (((uint)local_94 & 0x80) == 0) {
          if (((uint)local_94 & 4) != 0) goto LAB_00405ad1;
          if (((uint)local_94 & 2) != 0) goto LAB_00405fc0;
          if (((uint)local_94 & 1) != 0) {
            if (local_74 != (_IFP *)0x0) {
                    /* Unresolved local var: va_list ap@[???] */
              p_Var21 = (_IFP *)0x0;
              p_Var33 = local_74;
              while (p_Var33 = (_IFP *)((int)p_Var33 + -1), p_Var33 != (_IFP *)0x0) {
                p_Var21 = (_IFP *)0x1;
              }
              goto LAB_00405563;
            }
            goto LAB_00404f37;
          }
          if (local_74 != (_IFP *)0x0) {
            p_Var21 = (_IFP *)0x0;
            p_Var33 = local_74;
            while (p_Var33 = (_IFP *)((int)p_Var33 + -1), p_Var33 != (_IFP *)0x0) {
              p_Var21 = (_IFP *)0x1;
            }
            goto LAB_0040624d;
          }
          goto LAB_00405add;
        }
      }
      else {
        uVar19 = strtol((char *)p_Var21,(char **)in_stack_ffffff48,(int)local_84);
        if (p_Var21 == (_IFP *)tmp_wbuf_ptr) {
LAB_00404092:
          iVar14 = cleanup_return((int)local_98,&gcollect,&wbuf,(char **)in_stack_ffffff48);
          return iVar14;
        }
        p_Var21 = extraout_ECX_27;
        if (((uint)local_94 & 0x80) == 0) {
          if (((uint)local_94 & 4) == 0) {
            if (((uint)local_94 & 2) != 0) {
LAB_00405fc0:
              if (local_74 == (_IFP *)0x0) {
                puVar32 = (local_80->field_0).fp;
                p_Var21 = (_IFP *)local_80->bch;
                local_80 = p_Var21;
              }
              else {
                    /* Unresolved local var: va_list ap@[???] */
                p_Var21 = (_IFP *)((int)local_74 + -1);
                p_Var33 = s;
                if (p_Var21 != (_IFP *)0x0) {
                  p_Var33 = (_IFP *)(s->bch + (int)local_74 + -2);
                }
                puVar32 = (p_Var33->field_0).fp;
              }
              *puVar32 = (short)uVar19;
              goto LAB_0040455d;
            }
            if (((uint)local_94 & 1) != 0) {
              if (local_74 != (_IFP *)0x0) {
                    /* Unresolved local var: va_list ap@[???] */
                p_Var21 = (_IFP *)0x0;
                p_Var33 = local_74;
                while (p_Var33 = (_IFP *)((int)p_Var33 + -1), p_Var33 != (_IFP *)0x0) {
                  p_Var21 = (_IFP *)0x1;
                }
LAB_00405563:
                p_Var33 = s;
                if ((char)p_Var21 != '\0') {
                  p_Var33 = (_IFP *)(s->bch + (int)local_74 + -2);
                  p_Var21 = s;
                }
                *(p_Var33->field_0).str = (char)uVar19;
                goto LAB_0040455d;
              }
LAB_00404f37:
              paVar8 = &local_80->field_0;
              local_80 = (_IFP *)local_80->bch;
              *paVar8->str = (char)uVar19;
              p_Var21 = local_80;
              goto LAB_0040455d;
            }
            if (local_74 != (_IFP *)0x0) {
                    /* Unresolved local var: va_list ap@[???] */
              p_Var21 = (_IFP *)0x0;
              p_Var33 = local_74;
              while (p_Var33 = (_IFP *)((int)p_Var33 + -1), p_Var33 != (_IFP *)0x0) {
                p_Var21 = (_IFP *)0x1;
              }
LAB_0040624d:
              p_Var33 = s;
              if ((char)p_Var21 != '\0') {
                p_Var33 = (_IFP *)(s->bch + (int)local_74 + -2);
                p_Var21 = s;
              }
                    /* Unresolved local var: va_list ap@[???] */
              *(undefined4 *)(p_Var33->field_0).fp = uVar19;
              goto LAB_0040455d;
            }
          }
          else {
LAB_00405ad1:
            if (local_74 != (_IFP *)0x0) {
                    /* Unresolved local var: va_list ap@[???] */
              p_Var21 = s;
              if ((_IFP *)((int)local_74 + -1) != (_IFP *)0x0) {
                p_Var21 = (_IFP *)(s->bch + (int)local_74 + -2);
              }
              *(undefined4 *)(p_Var21->field_0).fp = uVar19;
              p_Var21 = (_IFP *)((int)local_74 + -1);
              goto LAB_0040455d;
            }
          }
LAB_00405add:
          paVar8 = &local_80->field_0;
          local_80 = (_IFP *)local_80->bch;
          *(undefined4 *)paVar8->fp = uVar19;
          p_Var21 = local_80;
          goto LAB_0040455d;
        }
      }
    }
    else {
      in_stack_ffffff48 = (_IFP *)&tmp_wbuf_ptr;
      if (((uint)local_94 & 0x10) == 0) {
        uVar43 = strtoumax((char *)p_Var21,(char **)in_stack_ffffff48,(int)local_84);
        if (p_Var21 == (_IFP *)tmp_wbuf_ptr) goto LAB_00404092;
        p_Var21 = extraout_ECX_37;
        if (((uint)local_94 & 0x80) != 0) goto LAB_004034c4;
      }
      else {
        uVar43 = strtoimax((char *)p_Var21,(char **)in_stack_ffffff48,(int)local_84);
        if (p_Var21 == (_IFP *)tmp_wbuf_ptr) goto LAB_00404092;
        p_Var21 = extraout_ECX_17;
        if (((uint)local_94 & 0x80) != 0) goto LAB_00404562;
      }
      if (local_74 == (_IFP *)0x0) {
        puVar26 = (local_80->field_0).fp;
        p_Var21 = (_IFP *)local_80->bch;
        local_80 = p_Var21;
      }
      else {
                    /* Unresolved local var: va_list ap@[???] */
        p_Var21 = (_IFP *)((int)local_74 + -1);
        p_Var33 = s;
        if (p_Var21 != (_IFP *)0x0) {
          p_Var33 = (_IFP *)(s->bch + (int)local_74 + -2);
        }
        puVar26 = (p_Var33->field_0).fp;
      }
      *puVar26 = uVar43;
LAB_0040455d:
      local_90 = local_90 + 1;
    }
  }
LAB_00404562:
  p_Var33 = (_IFP *)0x0;
LAB_004034c4:
  cVar11 = *(char *)&local_ac->field_0;
  if (cVar11 == '\0') goto code_r0x004034d3;
  goto LAB_004033bb;
joined_r0x00404856:
  while (pgVar6 != (gcollect *)0x0) {
    pgVar4 = pgVar6->next;
    free(pgVar6);
    pgVar6 = pgVar4;
  }
  goto LAB_00403471;
joined_r0x0040540e:
  while (pgVar6 != (gcollect *)0x0) {
    pgVar4 = pgVar6->next;
    free(pgVar6);
    pgVar6 = pgVar4;
  }
  goto LAB_00403471;
LAB_00404762:
  do {
    uVar24 = (uint)p_Var21 & 0xff;
    p_Var21 = (_IFP *)((int)&(p_Var21->field_0).fp + 1);
    wbuf[uVar24] = '\x01';
    bVar23 = *(byte *)&local_ac->field_0;
  } while ((byte)p_Var21 < bVar23);
LAB_0040472f:
  if (bVar23 == 0) goto joined_r0x00404d9d;
  goto LAB_0040473a;
joined_r0x00405b9b:
  while (pgVar6 != (gcollect *)0x0) {
    pgVar4 = pgVar6->next;
    free(pgVar6);
    pgVar6 = pgVar4;
  }
  goto LAB_00403471;
joined_r0x00405be2:
  while (pgVar6 != (gcollect *)0x0) {
    pgVar4 = pgVar6->next;
    free(pgVar6);
    pgVar6 = pgVar4;
  }
  goto LAB_00403471;
code_r0x004034d3:
  pgVar6 = gcollect;
  pcVar18 = wbuf;
  if (p_Var33 != (_IFP *)0x0) {
    do {
      iVar14 = in_ch(p_Var33,&read_in);
      iVar15 = isspace(iVar14);
      p_Var33 = extraout_ECX_01;
    } while (iVar15 != 0);
    pgVar6 = gcollect;
    pcVar18 = wbuf;
    if (iVar14 != -1) {
                    /* Unresolved local var: FILE * fp@[???] */
      sVar16 = read_in - 1;
      if ((in_EAX->field_0x1004 & 1) == 0) {
        ungetc(iVar14,(in_EAX->field_0).fp);
        pgVar6 = gcollect;
        read_in = sVar16;
        pcVar18 = wbuf;
      }
      else {
        iVar15 = in_EAX->back_top;
        in_EAX->bch[iVar15] = iVar14;
        in_EAX->back_top = iVar15 + 1;
        read_in = sVar16;
      }
    }
  }
  while (pcVar38 = wbuf, wbuf = pcVar18, pgVar6 != (gcollect *)0x0) {
    pgVar4 = pgVar6->next;
    free(pgVar6);
    pgVar6 = pgVar4;
    pcVar18 = wbuf;
    wbuf = pcVar38;
  }
  gcollect = (gcollect *)0x0;
  if (local_98 != (char **)0x0) {
    free(*local_98);
    *local_98 = (char *)0x0;
  }
LAB_00403581:
  free(pcVar38);
  return local_90;
LAB_004038b6:
  piVar17 = __errno();
  *piVar17 = iVar14;
  p_Var21 = extraout_ECX_06;
  if (s_09 != (_IFP *)0xffffffff) {
                    /* Unresolved local var: FILE * fp@[???] */
    sVar16 = read_in - 1;
    if ((in_EAX->field_0x1004 & 1) == 0) {
      in_stack_ffffff48 = (in_EAX->field_0).fp;
      in_stack_ffffff44 = s_09;
      ungetc((int)s_09,(FILE *)in_stack_ffffff48);
      p_Var21 = extraout_ECX_34;
      read_in = sVar16;
    }
    else {
      iVar14 = in_EAX->back_top;
      in_EAX->bch[iVar14] = (int)s_09;
      in_EAX->back_top = iVar14 + 1;
      p_Var21 = in_EAX;
      read_in = sVar16;
    }
  }
LAB_00403910:
  if (bVar23 == 99) {
    p_Var33 = (_IFP *)((uint)local_94 & 4);
    if (((uint)local_94 & 4) == 0) {
      if (p_Var34 == (_IFP *)0xffffffff) {
        p_Var34 = (_IFP *)0x1;
      }
      if (((uint)local_94 & 0x80) != 0) {
        s_09 = (_IFP *)in_ch(p_Var21,&read_in);
        p_Var21 = extraout_ECX_15;
        if (s_09 == (_IFP *)0xffffffff) goto LAB_00404092;
        do {
          p_Var34 = (_IFP *)&p_Var34[-1].field_0x100f;
          if (p_Var34 == (_IFP *)0x0) break;
          s_09 = (_IFP *)in_ch(p_Var21,&read_in);
          p_Var21 = extraout_ECX_16;
        } while (s_09 != (_IFP *)0xffffffff);
        goto LAB_004034c4;
      }
      if (((uint)local_94 & 0x600) == 0) {
        if (local_74 == (_IFP *)0x0) {
          p_Var33 = (local_80->field_0).fp;
          local_80 = (_IFP *)local_80->bch;
        }
        else {
                    /* Unresolved local var: va_list ap@[???] */
          p_Var21 = (_IFP *)(s->bch + (int)local_74 + -2);
          if (local_74 == (_IFP *)0x1) {
            p_Var21 = s;
          }
          p_Var33 = (p_Var21->field_0).fp;
        }
        if (p_Var33 == (_IFP *)0x0) goto LAB_00404092;
      }
      else {
        if (local_74 == (_IFP *)0x0) {
          local_98 = (local_80->field_0).fp;
          local_80 = (_IFP *)local_80->bch;
        }
        else {
                    /* Unresolved local var: va_list ap@[???] */
          p_Var21 = (_IFP *)(s->bch + (int)local_74 + -2);
          if (local_74 == (_IFP *)0x1) {
            p_Var21 = s;
          }
          local_98 = (p_Var21->field_0).fp;
        }
        if (local_98 == (char **)0x0) goto LAB_00405af1;
        local_78 = (_IFP *)0x400;
        if ((int)p_Var34 < 0x401) {
          local_78 = p_Var34;
        }
        in_stack_ffffff44 = local_78;
        p_Var33 = (_IFP *)malloc((size_t)local_78);
        pgVar6 = gcollect;
        *local_98 = (char *)p_Var33;
        if (p_Var33 == (_IFP *)0x0) goto LAB_00404e56;
                    /* Unresolved local var: gcollect * np@[???] */
        if (gcollect == (gcollect *)0x0) {
LAB_00403e76:
          in_stack_ffffff44 = (_IFP *)0x88;
          sVar16 = 1;
          gcollect = (gcollect *)malloc(0x88);
          uVar24 = 0;
          gcollect->count = 0;
          gcollect->next = pgVar6;
        }
        else {
          uVar24 = gcollect->count;
          sVar16 = uVar24 + 1;
          if (0x1f < uVar24) goto LAB_00403e76;
        }
        gcollect->count = sVar16;
        gcollect->ptrs[uVar24] = local_98;
      }
      s_09 = (_IFP *)in_ch(p_Var33,&read_in);
      if (s_09 == (_IFP *)0xffffffff) goto LAB_00404092;
      p_Var27 = local_78;
      do {
        local_78 = p_Var27;
        if ((((uint)local_94 & 0x600) != 0) &&
           (p_Var21 = (_IFP *)*local_98,
           p_Var33 == (_IFP *)((int)p_Var27->bch + (int)(p_Var21->bch + -2)))) {
          p_Var33 = (_IFP *)&p_Var34[-1].field_0x100f;
          if ((int)p_Var27 < (int)p_Var34) {
            p_Var33 = p_Var27;
          }
          local_78 = (_IFP *)((int)p_Var33->bch + (int)(p_Var27->bch + -2));
          while (in_stack_ffffff48 = local_78, pcVar18 = (char *)realloc(p_Var21,(size_t)local_78),
                pcVar18 == (char *)0x0) {
            p_Var33 = (_IFP *)((int)&p_Var27->field_0 + 1);
            p_Var21 = (_IFP *)0x0;
            if (local_78 <= p_Var33) goto LAB_00404040;
            p_Var21 = (_IFP *)*local_98;
            local_78 = p_Var33;
          }
          *local_98 = pcVar18;
          p_Var33 = (_IFP *)((int)p_Var27->bch + (int)(pcVar18 + -4));
          in_stack_ffffff44 = p_Var21;
        }
        *(char *)&p_Var33->field_0 = (char)s_09;
        local_70 = (_IFP *)((int)&p_Var33->field_0 + 1);
        p_Var34 = (_IFP *)&p_Var34[-1].field_0x100f;
        p_Var21 = p_Var33;
      } while ((p_Var34 != (_IFP *)0x0) &&
              (s_09 = (_IFP *)in_ch(p_Var33,&read_in), p_Var33 = local_70, p_Var21 = extraout_ECX_10
              , p_Var27 = local_78, s_09 != (_IFP *)0xffffffff));
                    /* Unresolved local var: size_t need_sz@[???]
                       Unresolved local var: char * h@[???] */
      if ((local_98 != (char **)0x0) &&
         (((p_Var33 = (_IFP *)*local_98, p_Var33 != (_IFP *)0x0 &&
           (p_Var27 = (_IFP *)((int)local_70 - (int)p_Var33), local_78 != p_Var27)) &&
          (pcVar18 = (char *)realloc(p_Var33,(size_t)p_Var27), p_Var21 = extraout_ECX_26,
          in_stack_ffffff44 = p_Var33, in_stack_ffffff48 = p_Var27, pcVar18 != (char *)0x0)))) {
        *local_98 = pcVar18;
      }
      local_90 = local_90 + 1;
      p_Var33 = (_IFP *)0x0;
      local_98 = (char **)0x0;
      goto LAB_004034c4;
    }
switchD_00403942_caseD_43:
    if (p_Var34 == (_IFP *)0xffffffff) {
      p_Var34 = (_IFP *)0x1;
    }
    uVar24 = (uint)local_94 & 0x80;
    if (((uint)local_94 & 0x80) == 0) {
      if (((uint)local_94 & 0x600) == 0) {
        if (local_74 == (_IFP *)0x0) {
          local_7c = (local_80->field_0).fp;
          local_80 = (_IFP *)local_80->bch;
        }
        else {
                    /* Unresolved local var: va_list ap@[???] */
          p_Var33 = (_IFP *)(s->bch + (int)local_74 + -2);
          if (local_74 == (_IFP *)0x1) {
            p_Var33 = s;
          }
          local_7c = (p_Var33->field_0).fp;
        }
        if (local_7c == (_IFP *)0x0) goto LAB_00404092;
      }
      else {
        if (local_74 == (_IFP *)0x0) {
          local_98 = (local_80->field_0).fp;
          local_80 = (_IFP *)local_80->bch;
        }
        else {
                    /* Unresolved local var: va_list ap@[???] */
          p_Var21 = (_IFP *)(s->bch + (int)local_74 + -2);
          if (local_74 == (_IFP *)0x1) {
            p_Var21 = s;
          }
          local_98 = (p_Var21->field_0).fp;
        }
        if (local_98 == (char **)0x0) goto LAB_00405af1;
        local_78 = (_IFP *)0x400;
        if ((int)p_Var34 < 0x401) {
          local_78 = p_Var34;
        }
        local_7c = (_IFP *)malloc((int)local_78 * 2);
        pgVar6 = gcollect;
        *local_98 = (char *)local_7c;
        if (local_7c == (_IFP *)0x0) goto LAB_00404e56;
                    /* Unresolved local var: gcollect * np@[???] */
        if (gcollect == (gcollect *)0x0) {
LAB_00403b3b:
          gcollect = (gcollect *)malloc(0x88);
          p_Var21 = (_IFP *)0x1;
          uVar25 = 0;
          gcollect->count = 0;
          gcollect->next = pgVar6;
        }
        else {
          uVar25 = gcollect->count;
          p_Var21 = (_IFP *)(uVar25 + 1);
          if (0x1f < uVar25) goto LAB_00403b3b;
        }
        gcollect->count = (size_t)p_Var21;
        gcollect->ptrs[uVar25] = local_98;
      }
    }
    s_09 = (_IFP *)in_ch(p_Var21,&read_in);
    if (s_09 == (_IFP *)0xffffffff) {
      p_Var21 = extraout_ECX_07;
      pgVar6 = gcollect;
      if (local_90 != 0) goto joined_r0x00405be2;
LAB_00404040:
      release_ptrs((gcollect **)p_Var21,&wbuf);
      return -1;
    }
    cstate._Wchar = 0;
    cstate._Byte = L'\0';
    cstate._State = L'\0';
    local_74 = p_Var34;
    do {
      buf[0] = (char)s_09;
      if ((uVar24 == 0) && (((uint)local_94 & 0x600) != 0)) {
        pcVar18 = *local_98;
        if (local_7c == (_IFP *)(pcVar18 + (int)local_78 * 2)) {
          p_Var21 = (_IFP *)&local_74[-1].field_0x100f;
          if ((int)local_78 <= (int)local_74) {
            p_Var21 = local_78;
          }
          p_Var33 = (_IFP *)((int)p_Var21->bch + (int)(local_78->bch + -2));
          while (pcVar18 = (char *)realloc(pcVar18,(int)p_Var33 * 2), pcVar18 == (char *)0x0) {
            p_Var21 = (_IFP *)((int)&local_78->field_0 + 1);
            if (p_Var33 <= p_Var21) goto LAB_00404040;
            pcVar18 = *local_98;
            p_Var33 = p_Var21;
          }
          *local_98 = pcVar18;
          local_7c = (_IFP *)(pcVar18 + (int)local_78 * 2);
          local_78 = p_Var33;
        }
      }
      p_Var21 = (_IFP *)0x0;
      if (uVar24 == 0) {
        p_Var21 = local_7c;
      }
      while( true ) {
        in_stack_ffffff48 = (_IFP *)buf;
        in_stack_ffffff44 = p_Var21;
        sVar16 = mbrtowc((wchar_t *)p_Var21,(char *)in_stack_ffffff48,1,(mbstate_t *)&cstate);
        if (sVar16 != 0xfffffffe) break;
        s_09 = (_IFP *)in_ch(s_02,&read_in);
        if (s_09 == (_IFP *)0xffffffff) {
          piVar17 = __errno();
                    /* Unresolved local var: gcollect * pf@[???]
                       Unresolved local var: gcollect * pf_sv@[???] */
          *piVar17 = 0x2a;
          pgVar6 = gcollect;
          while (pgVar6 != (gcollect *)0x0) {
            pgVar4 = pgVar6->next;
            free(pgVar6);
            pgVar6 = pgVar4;
          }
          goto LAB_00403471;
        }
        buf[0] = (char)s_09;
      }
      if (sVar16 != 1) goto LAB_00405fb0;
      local_7c = (_IFP *)((int)&local_7c->field_0 + 2);
      local_74 = (_IFP *)&local_74[-1].field_0x100f;
      p_Var21 = (_IFP *)&read_in;
    } while ((local_74 != (_IFP *)0x0) &&
            (s_09 = (_IFP *)in_ch((_IFP *)&read_in,&read_in), p_Var21 = extraout_ECX_20,
            s_09 != (_IFP *)0xffffffff));
    if (uVar24 == 0) {
      optimize_alloc((char **)((int)local_78 * 2),(char *)local_7c,(size_t)in_stack_ffffff44);
      local_90 = local_90 + 1;
      local_98 = (char **)0x0;
      p_Var33 = (_IFP *)0x0;
      p_Var21 = extraout_ECX_21;
      goto LAB_004034c4;
    }
    goto LAB_00404562;
  }
  if (bVar23 == 0x73) {
    if (((uint)local_94 & 4) == 0) goto LAB_00403c9b;
switchD_00403942_caseD_53:
    uVar24 = (uint)local_94 & 0x80;
    if (((uint)local_94 & 0x80) == 0) {
      if (((uint)local_94 & 0x600) == 0) {
        if (local_74 == (_IFP *)0x0) {
          local_7c = (_IFP *)(local_80->field_0).str;
          local_80 = (_IFP *)local_80->bch;
        }
        else {
                    /* Unresolved local var: va_list ap@[???] */
          p_Var33 = (_IFP *)(s->bch + (int)local_74 + -2);
          if (local_74 == (_IFP *)0x1) {
            p_Var33 = s;
          }
          local_7c = (_IFP *)(p_Var33->field_0).str;
        }
        if (local_7c == (_IFP *)0x0) goto LAB_00404092;
      }
      else {
        if (local_74 == (_IFP *)0x0) {
          local_98 = (local_80->field_0).fp;
          local_80 = (_IFP *)local_80->bch;
        }
        else {
                    /* Unresolved local var: va_list ap@[???] */
          p_Var21 = (_IFP *)(s->bch + (int)local_74 + -2);
          if (local_74 == (_IFP *)0x1) {
            p_Var21 = s;
          }
          local_98 = (p_Var21->field_0).fp;
        }
        if (local_98 == (char **)0x0) goto LAB_00405af1;
        local_7c = (_IFP *)malloc(200);
        pgVar6 = gcollect;
        *local_98 = (char *)local_7c;
        if (local_7c == (_IFP *)0x0) goto LAB_00404e56;
                    /* Unresolved local var: gcollect * np@[???] */
        if (gcollect == (gcollect *)0x0) {
LAB_004039c3:
          gcollect = (gcollect *)malloc(0x88);
          p_Var21 = (_IFP *)0x1;
          uVar25 = 0;
          gcollect->count = 0;
          gcollect->next = pgVar6;
        }
        else {
          uVar25 = gcollect->count;
          p_Var21 = (_IFP *)(uVar25 + 1);
          if (0x1f < uVar25) goto LAB_004039c3;
        }
        gcollect->count = (size_t)p_Var21;
        gcollect->ptrs[uVar25] = local_98;
        local_78 = (_IFP *)0x64;
      }
    }
    ppcVar9 = local_98;
    s_09 = (_IFP *)in_ch(p_Var21,&read_in);
    if (s_09 == (_IFP *)0xffffffff) {
      p_Var21 = (_IFP *)0x0;
      pgVar6 = gcollect;
      if (local_90 != 0) goto joined_r0x00405b9b;
      goto LAB_00404040;
    }
    cstate._Wchar = 0;
    cstate._Byte = L'\0';
    cstate._State = L'\0';
    local_74 = p_Var34;
    while (in_stack_ffffff44 = s_09, iVar14 = isspace((int)s_09), iVar14 == 0) {
      p_Var21 = (_IFP *)0x0;
      if (uVar24 == 0) {
        p_Var21 = local_7c;
      }
      while( true ) {
        in_stack_ffffff48 = (_IFP *)buf;
        buf[0] = (char)s_09;
        in_stack_ffffff44 = p_Var21;
        sVar16 = mbrtowc((wchar_t *)p_Var21,(char *)in_stack_ffffff48,1,(mbstate_t *)&cstate);
        if (sVar16 != 0xfffffffe) break;
        s_09 = (_IFP *)in_ch(s_01,&read_in);
        if (s_09 == (_IFP *)0xffffffff) {
          piVar17 = __errno();
                    /* Unresolved local var: gcollect * pf@[???]
                       Unresolved local var: gcollect * pf_sv@[???] */
          *piVar17 = 0x2a;
          pgVar6 = gcollect;
          while (pgVar6 != (gcollect *)0x0) {
            pgVar4 = pgVar6->next;
            free(pgVar6);
            pgVar6 = pgVar4;
          }
          goto LAB_00403471;
        }
      }
      if (sVar16 != 1) goto LAB_00405fb0;
      local_7c = (_IFP *)((int)&local_7c->field_0 + 2);
      p_Var21 = (_IFP *)&read_in;
      if (((uVar24 == 0) && (((uint)local_94 & 0x600) != 0)) &&
         (p_Var21 = (_IFP *)((int)local_78 * 2), p_Var33 = p_Var21,
         local_7c == (_IFP *)((int)p_Var21->bch + (int)(*local_98 + -4)))) {
        while( true ) {
          in_stack_ffffff48 = (_IFP *)((int)p_Var33 * 2);
          in_stack_ffffff44 = (_IFP *)*local_98;
          pcVar18 = (char *)realloc(in_stack_ffffff44,(size_t)in_stack_ffffff48);
          if (pcVar18 != (char *)0x0) break;
          p_Var27 = (_IFP *)((int)&local_78->field_0 + 1);
          bVar41 = p_Var33 <= p_Var27;
          p_Var33 = p_Var27;
          if (bVar41) {
            if (((uint)local_94 & 0x400) == 0) {
              local_98 = (char **)0x0;
              pcVar18 = (char *)((int)p_Var21->bch + (int)(*ppcVar9 + -6));
              pcVar18[0] = '\0';
              pcVar18[1] = '\0';
            }
            goto LAB_004061f1;
          }
        }
        *local_98 = pcVar18;
        local_7c = (_IFP *)((int)p_Var21->bch + (int)(pcVar18 + -4));
        local_78 = p_Var33;
      }
      if (((0 < (int)local_74) &&
          (local_74 = (_IFP *)&local_74[-1].field_0x100f, local_74 == (_IFP *)0x0)) ||
         (s_09 = (_IFP *)in_ch(p_Var21,&read_in), p_Var21 = extraout_ECX_19,
         s_09 == (_IFP *)0xffffffff)) goto LAB_00405c33;
    }
                    /* Unresolved local var: FILE * fp@[???] */
    sVar16 = read_in - 1;
    if ((in_EAX->field_0x1004 & 1) == 0) {
      in_stack_ffffff48 = (in_EAX->field_0).fp;
      in_stack_ffffff44 = s_09;
      ungetc((int)s_09,(FILE *)in_stack_ffffff48);
      p_Var21 = extraout_ECX_51;
      read_in = sVar16;
    }
    else {
      iVar14 = in_EAX->back_top;
      in_EAX->bch[iVar14] = (int)s_09;
      in_EAX->back_top = iVar14 + 1;
      p_Var21 = in_EAX;
      read_in = sVar16;
    }
LAB_00405c33:
    if (uVar24 == 0) {
      p_Var27 = (_IFP *)((int)&local_7c->field_0 + 2);
      *(undefined2 *)&local_7c->field_0 = 0;
      optimize_alloc((char **)((int)local_78 * 2),(char *)p_Var27,(size_t)in_stack_ffffff44);
      local_90 = local_90 + 1;
      local_98 = (char **)0x0;
      p_Var33 = (_IFP *)0x0;
      p_Var21 = extraout_ECX_45;
      local_7c = p_Var27;
      goto LAB_004034c4;
    }
    goto LAB_00404562;
  }
  if ((char)bVar23 < 'h') {
    if ('$' < (char)bVar23) {
      switch(uVar24 - 0x25 & 0xff) {
      case 0:
        s_09 = (_IFP *)in_ch(p_Var21,&read_in);
        if (s_09 == (_IFP *)0xffffffff) goto LAB_00404e56;
        p_Var21 = extraout_ECX_18;
        if (s_09 != (_IFP *)0x25) {
          back_ch((int)&read_in,in_EAX,(size_t *)0x1,(int)in_stack_ffffff48);
          goto LAB_00404092;
        }
        goto LAB_00404562;
      default:
        goto switchD_00403942_caseD_26;
      case 0x1c:
      case 0x20:
      case 0x21:
      case 0x22:
      case 0x3c:
      case 0x40:
      case 0x41:
      case 0x42:
        if ((int)p_Var34 < 0) {
          p_Var34 = (_IFP *)0x0;
        }
        puVar1 = &p_Var34[-1].field_0x100f;
        p_Var33 = (_IFP *)in_ch(p_Var21,&read_in);
        if (p_Var33 == (_IFP *)0xffffffff) goto LAB_00404e56;
        s_09 = p_Var33;
        local_64 = (_IFP *)puVar1;
        if (((uint)((int)p_Var33[-1].bch + 0xfe1) & 0xfffffffd) == 0) {
          if ((puVar1 == (undefined1 *)0x0) ||
             (s_09 = (_IFP *)in_ch(s_03,&read_in), s_09 == (_IFP *)0xffffffff)) goto LAB_00404092;
          local_64 = (_IFP *)0xffffffff;
          if (0 < (int)puVar1) {
            local_64 = (_IFP *)&p_Var34[-1].field_0x100e;
          }
        }
        p_Var21 = s_09;
        iVar14 = tolower((int)s_09);
        cVar11 = (char)s_09;
        if (iVar14 == 0x6e) {
                    /* Unresolved local var: char * match_txt@[???] */
          p_Var27 = (_IFP *)resize_wbuf((size_t)wbuf,&wbuf_max_sz,(char *)p_Var21);
          *(char *)&p_Var27->field_0 = cVar11;
          iVar14 = 1;
          p_Var34 = p_Var27;
          do {
            pgVar6 = gcollect;
            wbuf = (char *)p_Var34;
            if (((local_64 == (_IFP *)0x0) ||
                (s_09 = (_IFP *)in_ch(p_Var27,&read_in), pgVar6 = gcollect,
                s_09 == (_IFP *)0xffffffff)) ||
               (p_Var21 = s_09, iVar15 = tolower((int)s_09), pgVar6 = gcollect,
               iVar15 != (char)(&UNK_004113de)[iVar14])) {
              while (pgVar6 != (gcollect *)0x0) {
                pgVar4 = pgVar6->next;
                free(pgVar6);
                pgVar6 = pgVar4;
              }
              gcollect = (gcollect *)0x0;
              if (local_98 != (char **)0x0) {
                free(*local_98);
                *local_98 = (char *)0x0;
              }
              free(p_Var34);
              return local_90;
            }
            local_64 = (_IFP *)((int)local_64 - (uint)(0 < (int)local_64));
            p_Var34 = (_IFP *)resize_wbuf((size_t)p_Var34,&wbuf_max_sz,(char *)p_Var21);
            cVar11 = (&DAT_004113df)[iVar14];
            iVar15 = iVar14 + 1;
            *(char *)((int)p_Var34->bch + iVar14 + -4) = (char)s_09;
            p_Var27 = extraout_ECX_48;
            iVar14 = iVar15;
            wbuf = (char *)p_Var34;
          } while (cVar11 != '\0');
        }
        else if (iVar14 == 0x69) {
                    /* Unresolved local var: char * match_txt@[???] */
          s_09 = (_IFP *)resize_wbuf((size_t)wbuf,&wbuf_max_sz,(char *)p_Var21);
          *(char *)&s_09->field_0 = cVar11;
          iVar15 = 1;
          p_Var27 = s_09;
          do {
            iVar14 = iVar15;
            pgVar6 = gcollect;
            wbuf = (char *)p_Var27;
            if (((local_64 == (_IFP *)0x0) ||
                (s_09 = (_IFP *)in_ch(s_09,&read_in), pgVar6 = gcollect, s_09 == (_IFP *)0xffffffff)
                ) || (p_Var21 = s_09, iVar15 = tolower((int)s_09), pgVar6 = gcollect,
                     iVar15 != (char)(&UNK_004113e2)[iVar14])) {
              while (pgVar6 != (gcollect *)0x0) {
                pgVar4 = pgVar6->next;
                free(pgVar6);
                pgVar6 = pgVar4;
              }
              gcollect = (gcollect *)0x0;
              if (local_98 != (char **)0x0) {
                free(*local_98);
                *local_98 = (char *)0x0;
              }
              free(p_Var27);
              return local_90;
            }
            local_64 = (_IFP *)((int)local_64 - (uint)(0 < (int)local_64));
            p_Var27 = (_IFP *)resize_wbuf((size_t)p_Var27,&wbuf_max_sz,(char *)p_Var21);
            cVar11 = (&DAT_004113e3)[iVar14];
            iVar15 = iVar14 + 1;
            *(char *)((int)p_Var27->bch + iVar14 + -4) = (char)s_09;
          } while (cVar11 != '\0');
          wbuf = (char *)p_Var27;
          if ((local_64 != (_IFP *)0x0) &&
             (s_09 = (_IFP *)in_ch(s_09,&read_in), s_09 != (_IFP *)0xffffffff)) {
            p_Var21 = s_09;
            iVar39 = tolower((int)s_09);
            if (iVar39 == 0x69) {
              if (0 < (int)local_64) {
                local_64 = (_IFP *)&local_64[-1].field_0x100f;
              }
              wbuf = resize_wbuf((size_t)p_Var27,&wbuf_max_sz,(char *)p_Var21);
              local_68 = "inity";
              wbuf[iVar15] = (char)s_09;
              iVar14 = iVar14 + 2;
              do {
                if (((local_64 == (_IFP *)0x0) ||
                    (s_09 = (_IFP *)in_ch(s_09,&read_in), s_09 == (_IFP *)0xffffffff)) ||
                   (p_Var21 = s_09, iVar15 = tolower((int)s_09), iVar15 != local_68[1]))
                goto LAB_00404092;
                if (0 < (int)local_64) {
                  local_64 = (_IFP *)&local_64[-1].field_0x100f;
                }
                wbuf = resize_wbuf((size_t)wbuf,&wbuf_max_sz,(char *)p_Var21);
                iVar15 = iVar14 + 1;
                wbuf[iVar14] = (char)s_09;
                pcVar18 = local_68 + 2;
                iVar14 = iVar15;
                local_68 = local_68 + 1;
              } while (*pcVar18 != '\0');
            }
            else {
              p_Var21 = (_IFP *)0x0;
              back_ch((int)&read_in,in_EAX,(size_t *)0x0,(int)in_stack_ffffff48);
            }
          }
        }
        else {
          bVar23 = 0x65;
          iVar15 = 0;
          if ((local_64 != (_IFP *)0x0) && (s_09 == (_IFP *)0x30)) {
            pcVar18 = resize_wbuf((size_t)wbuf,&wbuf_max_sz,(char *)p_Var21);
            *pcVar18 = '0';
            wbuf = pcVar18;
            s_09 = (_IFP *)in_ch(s_08,&read_in);
            if ((int)local_64 < 1) {
              local_64 = (_IFP *)0xffffffff;
            }
            else {
              local_64 = (_IFP *)&local_64[-1].field_0x100f;
              iVar15 = 1;
              if (local_64 == (_IFP *)0x0) goto LAB_00404248;
            }
            p_Var21 = s_09;
            iVar14 = tolower((int)s_09);
            if (iVar14 == 0x78) {
              wbuf = resize_wbuf((size_t)pcVar18,&wbuf_max_sz,(char *)p_Var21);
              wbuf[1] = (char)s_09;
              local_94 = (_IFP *)((uint)local_94 & 0xfffffeff | 0x40);
              s_09 = (_IFP *)in_ch(s_09,&read_in);
              bVar23 = 0x70;
              iVar15 = 2;
              p_Var27 = (_IFP *)0x0;
              if (-1 < (int)local_64) {
                p_Var27 = local_64;
              }
              local_64 = (_IFP *)&p_Var27[-1].field_0x100f;
            }
            else {
              bVar23 = 0x65;
              iVar15 = 1;
            }
          }
LAB_00404248:
                    /* Unresolved local var: char * p@[???]
                       Unresolved local var: int remain@[???]
                       Unresolved local var: char * pp@[???] */
          bVar7 = false;
          bVar41 = false;
LAB_004042fe:
          p_Var27 = local_64;
          if (s_09[-1].bch + 0x3f7 < (int *)0xa) {
LAB_00404340:
            wbuf = resize_wbuf((size_t)wbuf,&wbuf_max_sz,(char *)p_Var21);
            wbuf[iVar15] = (char)s_09;
            p_Var34 = extraout_ECX_14;
            iVar15 = iVar15 + 1;
LAB_004042d5:
            local_64 = p_Var34;
            if (p_Var27 == (_IFP *)0x0) goto LAB_00404cb4;
LAB_004042dd:
            s_09 = (_IFP *)in_ch(local_64,&read_in);
            if (s_09 == (_IFP *)0xffffffff) goto LAB_00404cb4;
            local_64 = (_IFP *)((int)p_Var27 - (uint)(0 < (int)p_Var27));
            goto LAB_004042fe;
          }
          if (!bVar7) {
            if ((((uint)local_94 & 0x40) != 0) &&
               (p_Var21 = s_09, iVar14 = isxdigit((int)s_09), iVar14 != 0)) goto LAB_00404340;
            if ((iVar15 == 0) || (p_Var21 = s_09, bVar10 = tolower((int)s_09), bVar23 != bVar10))
            goto LAB_0040429b;
            wbuf = resize_wbuf((size_t)wbuf,&wbuf_max_sz,(char *)p_Var21);
            p_Var34 = (_IFP *)(uint)bVar23;
            bVar7 = true;
            wbuf[iVar15] = bVar23;
            iVar15 = iVar15 + 1;
            bVar41 = true;
            goto LAB_004042d5;
          }
          if ((wbuf[iVar15 + -1] == bVar23) &&
             (((uint)((int)s_09[-1].bch + 0xfe1U) & 0xfffffffd) == 0)) goto LAB_00404340;
LAB_0040429b:
          bVar10 = *pbVar3;
          p_Var35 = local_9c;
          if ((int)local_64 < 1) {
            if (!bVar41) {
              p_Var34 = (_IFP *)0x7fffffff;
              goto LAB_00404a41;
            }
            p_Var34 = (_IFP *)0x7fffffff;
            if (bVar10 == 0) goto LAB_004042d5;
            goto LAB_004042bb;
          }
          p_Var34 = local_64;
          if (bVar41) {
            if (bVar10 != 0) goto LAB_004042bb;
            goto LAB_004042dd;
          }
LAB_00404a41:
          p_Var22 = p_Var34;
          pbVar36 = pbVar3;
          pbVar37 = pbVar3;
          if ((_IFP *)(uint)bVar10 == s_09) {
            do {
              pbVar36 = pbVar37 + 1;
              if (*pbVar36 == 0) goto LAB_00404aa2;
              if (p_Var34 == (_IFP *)0x0) goto LAB_00404b3a;
              s_09 = (_IFP *)in_ch(p_Var22,&read_in);
              if (s_09 == (_IFP *)0xffffffff) {
                bVar10 = pbVar37[1];
                break;
              }
              bVar10 = *pbVar36;
              p_Var34 = (_IFP *)&p_Var34[-1].field_0x100f;
              p_Var22 = extraout_ECX_22;
              pbVar37 = pbVar36;
            } while (s_09 == (_IFP *)(uint)bVar10);
          }
          if (bVar10 == 0) {
LAB_00404aa2:
            bVar10 = *pbVar3;
            iVar14 = iVar15;
            while (bVar10 != 0) {
              wbuf = resize_wbuf((size_t)wbuf,&wbuf_max_sz,(char *)p_Var21);
              iVar39 = iVar14 + 1;
              wbuf[iVar14] = pbVar3[iVar39 + (-1 - iVar15)];
              iVar14 = iVar39;
              bVar10 = pbVar3[iVar39 - iVar15];
            }
            iVar15 = iVar14;
            if ((int)local_64 < 1) {
              bVar41 = true;
            }
            else {
              bVar41 = true;
              p_Var27 = p_Var34;
            }
            goto LAB_004042d5;
          }
LAB_00404b3a:
          if (((uint)local_94 & 0x100) == 0) {
LAB_004042bb:
            p_Var22 = p_Var34;
            if (local_9c != (_IFP *)0x0) goto LAB_004042c7;
          }
          else {
            iVar39 = (int)pbVar36 - (int)pbVar3;
            iVar14 = 0;
            p_Var22 = p_Var34;
            if (iVar39 < 1) {
              if (pbVar36 != pbVar3) goto LAB_004042bb;
            }
            else {
              do {
                if (*(byte *)&p_Var35->field_0 != pbVar3[iVar14]) break;
                p_Var35 = (_IFP *)((int)&p_Var35->field_0 + 1);
                iVar14 = (int)p_Var35 - (int)local_9c;
              } while (iVar14 < iVar39);
              if (iVar39 != iVar14) goto LAB_004042c7;
            }
            if (s_09 == (_IFP *)(uint)*(byte *)&p_Var35->field_0) {
              do {
                p_Var35 = (_IFP *)((int)&p_Var35->field_0 + 1);
                if (((*(char *)&p_Var35->field_0 == '\0') || (p_Var22 == (_IFP *)0x0)) ||
                   (s_09 = (_IFP *)in_ch(p_Var34,&read_in), s_09 == (_IFP *)0xffffffff)) break;
                p_Var22 = (_IFP *)&p_Var22[-1].field_0x100f;
                p_Var34 = extraout_ECX_23;
              } while (s_09 == (_IFP *)(uint)*(byte *)&p_Var35->field_0);
            }
LAB_004042c7:
            if (*(char *)&p_Var35->field_0 == '\0') {
              p_Var34 = p_Var22;
              if (0 < (int)local_64) {
                p_Var27 = p_Var22;
              }
              goto LAB_004042d5;
            }
          }
          if (s_09 != (_IFP *)0xffffffff) {
                    /* Unresolved local var: FILE * fp@[???] */
            sVar16 = read_in - 1;
            if ((in_EAX->field_0x1004 & 1) == 0) {
              in_stack_ffffff48 = (in_EAX->field_0).fp;
              p_Var21 = s_09;
              ungetc((int)s_09,(FILE *)in_stack_ffffff48);
              read_in = sVar16;
            }
            else {
              iVar14 = in_EAX->back_top;
              in_EAX->bch[iVar14] = (int)s_09;
              in_EAX->back_top = iVar14 + 1;
              read_in = sVar16;
            }
          }
LAB_00404cb4:
          if ((iVar15 == 0) || ((((uint)local_94 & 0x40) != 0 && (iVar15 == 2)))) goto LAB_00404092;
        }
        p_Var27 = (_IFP *)resize_wbuf((size_t)wbuf,&wbuf_max_sz,(char *)p_Var21);
        *(undefined1 *)((int)p_Var27->bch + iVar15 + -4) = 0;
        uVar24 = (uint)local_94 & 0x80;
        in_stack_ffffff48 = (_IFP *)&tmp_wbuf_ptr;
        in_stack_ffffff44 = p_Var27;
        wbuf = (char *)p_Var27;
        if (((uint)local_94 & 8) == 0) {
          if (((uint)local_94 & 4) == 0) {
            fVar44 = __strtof((char *)p_Var27,(char **)in_stack_ffffff48);
            p_Var21 = extraout_ECX_38;
            if (uVar24 != 0) goto LAB_00405434;
            if (p_Var27 == (_IFP *)tmp_wbuf_ptr) goto LAB_00404092;
            fVar5 = -fVar44;
            if (p_Var33 != (_IFP *)0x2d) {
              fVar5 = fVar44;
            }
            if (local_74 == (_IFP *)0x0) {
              pfVar29 = (local_80->field_0).fp;
              local_80 = (_IFP *)local_80->bch;
            }
            else {
                    /* Unresolved local var: va_list ap@[???] */
              p_Var21 = s;
              if (local_74 != (_IFP *)0x1) {
                p_Var21 = (_IFP *)(s->bch + (int)local_74 + -2);
              }
              pfVar29 = (p_Var21->field_0).fp;
            }
            *pfVar29 = fVar5;
          }
          else {
            __strtold((char *)p_Var27,(char **)in_stack_ffffff48);
            p_Var21 = extraout_ECX_25;
            if (uVar24 != 0) {
LAB_00405434:
              if (p_Var27 == (_IFP *)tmp_wbuf_ptr) goto LAB_00404092;
              goto LAB_00404562;
            }
            if (p_Var27 == (_IFP *)tmp_wbuf_ptr) goto LAB_00404092;
            dVar2 = (double)extraout_ST0;
            if (p_Var33 == (_IFP *)0x2d) {
              dVar2 = -dVar2;
            }
            if (local_74 == (_IFP *)0x0) {
              pdVar28 = (local_80->field_0).fp;
              local_80 = (_IFP *)local_80->bch;
            }
            else {
                    /* Unresolved local var: va_list ap@[???] */
              p_Var21 = s;
              if (local_74 != (_IFP *)0x1) {
                p_Var21 = (_IFP *)(s->bch + (int)local_74 + -2);
              }
              pdVar28 = (p_Var21->field_0).fp;
            }
            *pdVar28 = dVar2;
          }
        }
        else {
          __strtold((char *)p_Var27,(char **)in_stack_ffffff48);
          p_Var21 = extraout_ECX_39;
          if (uVar24 != 0) goto LAB_00405434;
          if (p_Var27 == (_IFP *)tmp_wbuf_ptr) goto LAB_00404092;
          fVar42 = extraout_ST0_00;
          if (p_Var33 == (_IFP *)0x2d) {
            fVar42 = -extraout_ST0_00;
          }
          if (local_74 == (_IFP *)0x0) {
            pfVar30 = (local_80->field_0).fp;
            local_80 = (_IFP *)local_80->bch;
          }
          else {
                    /* Unresolved local var: va_list ap@[???] */
            p_Var21 = s;
            if (local_74 != (_IFP *)0x1) {
              p_Var21 = (_IFP *)(s->bch + (int)local_74 + -2);
            }
            pfVar30 = (p_Var21->field_0).fp;
          }
          *pfVar30 = fVar42;
        }
        p_Var21 = (_IFP *)tmp_wbuf_ptr;
        if (p_Var27 == (_IFP *)tmp_wbuf_ptr) goto LAB_00404092;
        break;
      case 0x1e:
        goto switchD_00403942_caseD_43;
      case 0x2e:
        goto switchD_00403942_caseD_53;
      case 0x33:
      case 0x3f:
        goto switchD_00403942_caseD_58;
      case 0x36:
        p_Var27 = (_IFP *)((uint)local_94 & 0x80);
        if (((uint)local_94 & 4) == 0) {
          if (p_Var27 == (_IFP *)0x0) {
            if (((uint)local_94 & 0x600) == 0) {
              if (local_74 == (_IFP *)0x0) {
                local_70 = (local_80->field_0).fp;
                local_80 = (_IFP *)local_80->bch;
                p_Var21 = local_70;
              }
              else {
                    /* Unresolved local var: va_list ap@[???] */
                p_Var21 = (_IFP *)(s->bch + (int)local_74 + -2);
                if (local_74 == (_IFP *)0x1) {
                  p_Var21 = s;
                }
                local_70 = (p_Var21->field_0).fp;
                p_Var21 = local_70;
              }
              goto joined_r0x0040582c;
            }
            if (local_74 == (_IFP *)0x0) {
              local_98 = (local_80->field_0).fp;
              local_80 = (_IFP *)local_80->bch;
            }
            else {
                    /* Unresolved local var: va_list ap@[???] */
              p_Var21 = (_IFP *)(s->bch + (int)local_74 + -2);
              if (local_74 == (_IFP *)0x1) {
                p_Var21 = s;
              }
              local_98 = (p_Var21->field_0).fp;
            }
            if (local_98 == (char **)0x0) goto LAB_00405af1;
            in_stack_ffffff44 = (_IFP *)0x64;
            local_70 = (_IFP *)malloc(100);
            *local_98 = (char *)local_70;
            pgVar6 = gcollect;
            p_Var21 = local_70;
joined_r0x00404e3c:
            gcollect = pgVar6;
            if (p_Var21 == (_IFP *)0x0) goto LAB_00404e56;
                    /* Unresolved local var: gcollect * np@[???] */
            if (pgVar6 == (gcollect *)0x0) {
LAB_0040463b:
              in_stack_ffffff44 = (_IFP *)0x88;
              gcollect = (gcollect *)malloc(0x88);
              sVar16 = 1;
              uVar24 = 0;
              gcollect->count = 0;
              gcollect->next = pgVar6;
            }
            else {
              uVar24 = pgVar6->count;
              sVar16 = uVar24 + 1;
              if (0x1f < uVar24) goto LAB_0040463b;
            }
            gcollect->count = sVar16;
            gcollect->ptrs[uVar24] = local_98;
            local_78 = (_IFP *)0x64;
          }
        }
        else if (p_Var27 == (_IFP *)0x0) {
          if (((uint)local_94 & 0x600) != 0) {
            if (local_74 == (_IFP *)0x0) {
              local_98 = (local_80->field_0).fp;
              local_80 = (_IFP *)local_80->bch;
            }
            else {
                    /* Unresolved local var: va_list ap@[???] */
              p_Var21 = (_IFP *)(s->bch + (int)local_74 + -2);
              if (local_74 == (_IFP *)0x1) {
                p_Var21 = s;
              }
              local_98 = (p_Var21->field_0).fp;
            }
            if (local_98 == (char **)0x0) goto LAB_00405af1;
            in_stack_ffffff44 = (_IFP *)0xc8;
            local_7c = (_IFP *)malloc(200);
            *local_98 = (char *)local_7c;
            pgVar6 = gcollect;
            p_Var21 = local_7c;
            goto joined_r0x00404e3c;
          }
          if (local_74 == (_IFP *)0x0) {
            local_7c = (_IFP *)(local_80->field_0).str;
            local_80 = (_IFP *)local_80->bch;
            p_Var21 = local_7c;
          }
          else {
                    /* Unresolved local var: va_list ap@[???] */
            p_Var21 = (_IFP *)(s->bch + (int)local_74 + -2);
            if (local_74 == (_IFP *)0x1) {
              p_Var21 = s;
            }
            local_7c = (_IFP *)(p_Var21->field_0).str;
            p_Var21 = local_7c;
          }
joined_r0x0040582c:
          if (p_Var21 == (_IFP *)0x0) goto LAB_00404092;
        }
        cVar11 = *(char *)((int)&local_88->field_0 + 1);
        p_Var21 = (_IFP *)((int)&local_88->field_0 + 2);
        if (cVar11 != '^') {
          p_Var21 = local_ac;
        }
        if (p_Var34 == (_IFP *)0xffffffff) {
          p_Var34 = (_IFP *)0x7fffffff;
        }
        if (wbuf_max_sz < 0x100) {
          wbuf_max_sz = 0x100;
          if (wbuf != (char *)0x0) {
            free(wbuf);
          }
          in_stack_ffffff44 = (_IFP *)0x100;
          wbuf = (char *)malloc(0x100);
        }
        pcVar18 = wbuf;
        sVar16 = read_in;
        wbuf[0] = '\0';
        wbuf[1] = '\0';
        wbuf[2] = '\0';
        wbuf[3] = '\0';
        wbuf[0xfc] = '\0';
        wbuf[0xfd] = '\0';
        wbuf[0xfe] = '\0';
        wbuf[0xff] = '\0';
        puVar13 = (undefined4 *)((uint)(wbuf + 4) & 0xfffffffc);
        for (uVar24 = (uint)(wbuf + (0x100 - (int)((uint)(wbuf + 4) & 0xfffffffc))) >> 2;
            uVar24 != 0; uVar24 = uVar24 - 1) {
          *puVar13 = 0;
          puVar13 = puVar13 + 1;
        }
        bVar23 = *(byte *)&p_Var21->field_0;
        if ((bVar23 == 0x5d) || (local_ac = p_Var21, bVar23 == 0x2d)) {
          wbuf[(char)bVar23] = '\x01';
          local_ac = (_IFP *)((int)&p_Var21->field_0 + 1);
          bVar23 = *(byte *)&local_ac->field_0;
        }
        pgVar6 = gcollect;
        if (bVar23 == 0) {
joined_r0x00404d9d:
          while (pgVar6 != (gcollect *)0x0) {
            pgVar4 = pgVar6->next;
            free(pgVar6);
            pgVar6 = pgVar4;
          }
          gcollect = (gcollect *)0x0;
          if (local_98 != (char **)0x0) {
            free(*local_98);
            *local_98 = (char *)0x0;
          }
          free(pcVar18);
          return local_90;
        }
        p_Var21 = (_IFP *)0x0;
LAB_0040473a:
        local_ac = (_IFP *)((int)&local_ac->field_0 + 1);
        if (bVar23 != 0x5d) {
          for (; ((uVar24 = (uint)bVar23, bVar23 == 0x2d &&
                  (bVar23 = *(byte *)&local_ac->field_0, bVar23 != 0x5d)) && (bVar23 != 0));
              local_ac = (_IFP *)((int)&local_ac->field_0 + 1)) {
            bVar10 = local_ac[-1].field_0x100e;
            p_Var21 = (_IFP *)(uint)bVar10;
            if (bVar23 < bVar10) break;
            if (bVar10 < bVar23) goto LAB_00404762;
          }
          wbuf[uVar24] = '\x01';
          bVar23 = *(byte *)&local_ac->field_0;
          goto LAB_0040472f;
        }
        if (((uint)local_94 & 4) != 0) {
          s_09 = (_IFP *)in_ch(p_Var21,&read_in);
          if (s_09 == (_IFP *)0xffffffff) goto LAB_00404e56;
          iVar14 = 0;
          cstate._Wchar = 0;
          cstate._Byte = L'\0';
          cstate._State = L'\0';
          p_Var21 = extraout_ECX_28;
          do {
            if ((bool)pcVar18[(int)s_09] == (cVar11 == '^')) {
                    /* Unresolved local var: FILE * fp@[???] */
              sVar20 = read_in - 1;
              if ((in_EAX->field_0x1004 & 1) == 0) {
                in_stack_ffffff48 = (in_EAX->field_0).fp;
                in_stack_ffffff44 = s_09;
                ungetc((int)s_09,(FILE *)in_stack_ffffff48);
                read_in = sVar20;
              }
              else {
                iVar15 = in_EAX->back_top;
                in_EAX->bch[iVar15] = (int)s_09;
                in_EAX->back_top = iVar15 + 1;
                read_in = sVar20;
              }
              break;
            }
            if (p_Var27 == (_IFP *)0x0) {
              iVar14 = iVar14 + 1;
              buf[0] = (char)s_09;
              in_stack_ffffff48 = (_IFP *)buf;
              in_stack_ffffff44 = local_7c;
              sVar20 = mbrtowc((wchar_t *)local_7c,(char *)in_stack_ffffff48,1,(mbstate_t *)&cstate)
              ;
              p_Var21 = extraout_ECX_30;
              if (sVar20 != 0xfffffffe) {
                local_7c = (_IFP *)((int)&local_7c->field_0 + 2);
                if (((uint)local_94 & 0x600) == 0) {
                  iVar14 = 0;
                }
                else {
                  iVar14 = 0;
                  p_Var33 = (_IFP *)*local_98;
                  p_Var21 = (_IFP *)((int)local_78 * 2);
                  p_Var35 = p_Var21;
                  if (local_7c == (_IFP *)((int)p_Var21->bch + (int)(p_Var33->bch + -2))) {
                    while( true ) {
                      in_stack_ffffff48 = (_IFP *)((int)p_Var35 * 2);
                      pcVar38 = (char *)realloc(p_Var33,(size_t)in_stack_ffffff48);
                      if (pcVar38 != (char *)0x0) break;
                      p_Var22 = (_IFP *)((int)&local_78->field_0 + 1);
                      if (p_Var35 <= p_Var22) {
                        if (((uint)local_94 & 0x400) == 0) {
                          pcVar18 = (char *)((int)p_Var21->bch + (int)(*local_98 + -6));
                          pcVar18[0] = '\0';
                          pcVar18[1] = '\0';
                          local_98 = (char **)0x0;
                        }
                        goto LAB_004061f1;
                      }
                      p_Var33 = (_IFP *)*local_98;
                      p_Var35 = p_Var22;
                    }
                    iVar14 = 0;
                    *local_98 = pcVar38;
                    local_7c = (_IFP *)((int)p_Var21->bch + (int)(pcVar38 + -4));
                    in_stack_ffffff44 = p_Var33;
                    local_78 = p_Var35;
                  }
                }
                goto LAB_00404fc8;
              }
            }
            else {
LAB_00404fc8:
              p_Var34 = (_IFP *)&p_Var34[-1].field_0x100f;
              if (p_Var34 == (_IFP *)0x0) break;
            }
            s_09 = (_IFP *)in_ch(p_Var21,&read_in);
            p_Var21 = extraout_ECX_29;
          } while (s_09 != (_IFP *)0xffffffff);
          if (iVar14 == 0) {
            if (read_in != sVar16) {
              p_Var33 = (_IFP *)0x0;
              p_Var21 = p_Var27;
              if (p_Var27 == (_IFP *)0x0) {
                    /* Unresolved local var: size_t need_sz@[???]
                       Unresolved local var: char * h@[???] */
                *(undefined2 *)&local_7c->field_0 = 0;
                local_7c = (_IFP *)((int)&local_7c->field_0 + 2);
                if ((local_98 != (char **)0x0) &&
                   (p_Var21 = (_IFP *)*local_98, p_Var21 != (_IFP *)0x0)) {
                  p_Var33 = (_IFP *)((int)local_7c - (int)p_Var21);
                  p_Var27 = (_IFP *)((int)local_78 * 2);
                  if ((p_Var27 != p_Var33) &&
                     (pcVar18 = (char *)realloc(p_Var21,(size_t)p_Var33), p_Var27 = extraout_ECX_44,
                     in_stack_ffffff44 = p_Var21, in_stack_ffffff48 = p_Var33,
                     pcVar18 != (char *)0x0)) {
                    *local_98 = pcVar18;
                  }
                }
                local_90 = local_90 + 1;
                p_Var33 = (_IFP *)0x0;
                local_98 = (char **)0x0;
                p_Var21 = p_Var27;
              }
              goto LAB_004034c4;
            }
          }
          else {
LAB_00405fb0:
            piVar17 = __errno();
            *piVar17 = 0x2a;
          }
          goto LAB_00404092;
        }
        s_09 = (_IFP *)in_ch(p_Var21,&read_in);
        if (s_09 == (_IFP *)0xffffffff) goto LAB_00404e56;
        p_Var21 = extraout_ECX_41;
        p_Var33 = local_70;
        while (local_70 = p_Var33, (bool)pcVar18[(int)s_09] != (cVar11 == '^')) {
          if (p_Var27 == (_IFP *)0x0) {
            local_70 = (_IFP *)((int)&p_Var33->field_0 + 1);
            *(char *)&p_Var33->field_0 = (char)s_09;
            p_Var21 = s_09;
            if ((((uint)local_94 & 0x600) != 0) &&
               (p_Var33 = (_IFP *)*local_98, p_Var21 = p_Var33,
               local_70 == (_IFP *)((int)p_Var33->bch + (int)(local_78->bch + -2)))) {
              p_Var35 = (_IFP *)((int)local_78 * 2);
              while (in_stack_ffffff48 = p_Var35, pcVar38 = (char *)realloc(p_Var33,(size_t)p_Var35)
                    , pcVar38 == (char *)0x0) {
                p_Var21 = (_IFP *)((int)&(local_78->field_0).fp + 1);
                if (p_Var35 <= p_Var21) goto LAB_004061c8;
                p_Var33 = (_IFP *)*local_98;
                p_Var35 = p_Var21;
              }
              *local_98 = pcVar38;
              local_70 = (_IFP *)((int)local_78->bch + (int)(pcVar38 + -4));
              p_Var21 = extraout_ECX_46;
              in_stack_ffffff44 = p_Var33;
              local_78 = p_Var35;
            }
          }
          p_Var34 = (_IFP *)&p_Var34[-1].field_0x100f;
          if ((p_Var34 == (_IFP *)0x0) ||
             (s_09 = (_IFP *)in_ch(p_Var21,&read_in), p_Var21 = extraout_ECX_42, p_Var33 = local_70,
             s_09 == (_IFP *)0xffffffff)) goto LAB_0040595c;
        }
                    /* Unresolved local var: FILE * fp@[???] */
        sVar20 = read_in - 1;
        if ((in_EAX->field_0x1004 & 1) == 0) {
          in_stack_ffffff48 = (in_EAX->field_0).fp;
          in_stack_ffffff44 = s_09;
          ungetc((int)s_09,(FILE *)in_stack_ffffff48);
          p_Var21 = extraout_ECX_50;
          read_in = sVar20;
        }
        else {
          iVar14 = in_EAX->back_top;
          in_EAX->bch[iVar14] = (int)s_09;
          in_EAX->back_top = iVar14 + 1;
          p_Var21 = in_EAX;
          read_in = sVar20;
        }
LAB_0040595c:
        if (read_in == sVar16) goto LAB_00404092;
        p_Var33 = (_IFP *)0x0;
        if (p_Var27 == (_IFP *)0x0) {
                    /* Unresolved local var: size_t need_sz@[???]
                       Unresolved local var: char * h@[???] */
          *(char *)&local_70->field_0 = '\0';
          local_70 = (_IFP *)((int)&local_70->field_0 + 1);
          if ((((local_98 != (char **)0x0) && (p_Var33 = (_IFP *)*local_98, p_Var33 != (_IFP *)0x0))
              && (p_Var27 = (_IFP *)((int)local_70 - (int)p_Var33), local_78 != p_Var27)) &&
             (pcVar18 = (char *)realloc(p_Var33,(size_t)p_Var27), p_Var21 = extraout_ECX_43,
             in_stack_ffffff44 = p_Var33, in_stack_ffffff48 = p_Var27, pcVar18 != (char *)0x0)) {
            *local_98 = pcVar18;
          }
          local_90 = local_90 + 1;
          p_Var33 = (_IFP *)0x0;
          local_98 = (char **)0x0;
        }
        goto LAB_004034c4;
      }
      goto LAB_0040455d;
    }
  }
  else {
    p_Var21 = (_IFP *)(uVar24 - 0x69);
    if ((byte)p_Var21 < 0x10) goto LAB_00403793;
  }
switchD_00403942_caseD_26:
  pgVar6 = gcollect;
  while (pgVar6 != (gcollect *)0x0) {
    pgVar4 = pgVar6->next;
    free(pgVar6);
    pgVar6 = pgVar4;
  }
LAB_00403471:
                    /* Unresolved local var: gcollect * pf@[???]
                       Unresolved local var: gcollect * pf_sv@[???] */
  gcollect = (gcollect *)0x0;
  if (local_98 != (char **)0x0) {
    free(*local_98);
    *local_98 = (char *)0x0;
  }
  free(wbuf);
  return local_90;
}



// --- Function: __mingw_vfscanf @ 00406550 ---

/* WARNING: Unable to track spacebase fully for stack */
/* WARNING: Unknown calling convention */

int __mingw_vfscanf(FILE *s,char *format,va_list argp)

{
  char *format_00;
  uint uVar1;
  int iVar2;
  int iVar3;
  undefined4 *puVar4;
  _IFP ifp;
  undefined4 uStack_c;
  
  uStack_c = 0x40655c;
  uVar1 = ___chkstk_ms();
  iVar2 = -uVar1;
  format_00 = *(char **)(&stack0x0000101c + iVar2);
  puVar4 = (undefined4 *)(&stack0xfffffff8 + iVar2);
  for (iVar3 = 0x404; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar4 = 0;
    puVar4 = puVar4 + 1;
  }
  *(undefined4 *)(&stack0xfffffff8 + iVar2) = *(undefined4 *)(&stack0x00001018 + iVar2);
  *(undefined4 *)((int)&uStack_c + iVar2) = 0x40658a;
  iVar2 = __mingw_sformat(*(_IFP **)(&stack0x00001020 + iVar2),format_00,
                          *(va_list *)(&stack0xfffffff8 + iVar2));
  return iVar2;
}



// --- Function: __mingw_vsscanf @ 004065a0 ---

/* WARNING: Unable to track spacebase fully for stack */
/* WARNING: Unknown calling convention */

int __mingw_vsscanf(char *s,char *format,va_list argp)

{
  char *format_00;
  uint uVar1;
  int iVar2;
  int iVar3;
  undefined4 *puVar4;
  _IFP ifp;
  undefined4 uStack_c;
  
  uStack_c = 0x4065ac;
  uVar1 = ___chkstk_ms();
  iVar2 = -uVar1;
  format_00 = *(char **)(&stack0x0000101c + iVar2);
  puVar4 = (undefined4 *)(&stack0xfffffff8 + iVar2);
  for (iVar3 = 0x404; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar4 = 0;
    puVar4 = puVar4 + 1;
  }
  (&stack0x00000ffc)[iVar2] = 1;
  *(undefined4 *)(&stack0xfffffff8 + iVar2) = *(undefined4 *)(&stack0x00001018 + iVar2);
  *(undefined4 *)((int)&uStack_c + iVar2) = 0x4065e2;
  iVar2 = __mingw_sformat(*(_IFP **)(&stack0x00001020 + iVar2),format_00,
                          *(va_list *)(&stack0xfffffff8 + iVar2));
  return iVar2;
}



// --- Function: __strtof @ 004065f0 ---

/* WARNING: Unknown calling convention */

float __strtof(char *s,char **sp)

{
  uint uVar1;
  ULong bits [1];
  long expo;
  
                    /* Unresolved local var: int k@[???]
                       Unresolved local var: anon_union_4_2_9472fd7b u@[???] */
  uVar1 = __strtodg(s,sp,&__strtof::fpi0,&expo,bits);
  switch(uVar1 & 7) {
  default:
    bits[0] = 0;
    break;
  case 1:
  case 5:
    bits[0] = (expo + 0x96) * 0x800000 | bits[0] & 0x7fffff;
    break;
  case 2:
    break;
  case 3:
    bits[0] = 0x7f800000;
    break;
  case 4:
    bits[0] = 0x7fc00000;
  }
  if ((uVar1 & 8) != 0) {
    bits[0] = bits[0] | 0x80000000;
  }
  return (float)bits[0];
}



// --- Function: __strtold @ 00406690 ---

/* WARNING: Unknown calling convention */

long_double * __strtold(char *src,char **endptr)

{
  long_double *pauVar1;
  long expo;
  ULong bits [2];
  lD ret;
  
                    /* Unresolved local var: int k@[???]
                       Unresolved local var: UShort * L@[???] */
  pauVar1 = (long_double *)__strtodg(src,endptr,(FPI *)&_fpi0_0,&expo,bits);
  switch((uint)pauVar1 & 7) {
  case 1:
  case 5:
  case 2:
  default:
    break;
  case 3:
    break;
  case 4:
  }
  return pauVar1;
}



// --- Function: strtoimax @ 00406740 ---

/* WARNING: Unknown calling convention */

intmax_t strtoimax(char *nptr,char **endptr,int base)

{
  char cVar1;
  ulonglong uVar2;
  char cVar3;
  int iVar4;
  int iVar5;
  int *piVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  bool bVar11;
  longlong lVar12;
  uint local_28;
  
                    /* Unresolved local var: uintmax_t accum@[???]
                       Unresolved local var: int n@[???]
                       Unresolved local var: int minus@[???]
                       Unresolved local var: int toobig@[???] */
  if (endptr != (char **)0x0) {
    *endptr = nptr;
  }
  if ((base == 1) || (0x24 < (uint)base)) {
    piVar6 = __errno();
    *piVar6 = 0x21;
  }
  else {
    while( true ) {
      cVar1 = *nptr;
      iVar4 = isspace((int)cVar1);
      if (iVar4 == 0) break;
      nptr = nptr + 1;
    }
    cVar3 = cVar1;
    if (((int)cVar1 - 0x2bU & 0xfd) == 0) {
      cVar3 = nptr[1];
      nptr = nptr + 1;
    }
    if (base == 0) {
      base = 10;
      if (cVar3 != '0') goto LAB_004067b8;
      if ((nptr[1] & 0xdfU) == 0x58) goto LAB_00406930;
      local_28 = 8;
LAB_004069d8:
      uVar7 = (uint)(char)(cVar3 + -0x30);
    }
    else {
      if ((base == 0x10) && (cVar3 == '0')) {
        if ((nptr[1] & 0xdfU) != 0x58) {
          local_28 = 0x10;
          uVar7 = 0;
          goto LAB_00406807;
        }
LAB_00406930:
        cVar3 = nptr[2];
        base = 0x10;
        nptr = nptr + 2;
      }
LAB_004067b8:
      iVar4 = (int)cVar3;
      if (iVar4 - 0x30U < 10) {
        local_28 = base;
        goto LAB_004069d8;
      }
      iVar5 = isupper(iVar4);
      if (iVar5 == 0) {
        iVar5 = islower(iVar4);
        if (iVar5 == 0) goto LAB_004068fb;
        uVar7 = iVar4 - 0x57;
        local_28 = base;
      }
      else {
        local_28 = base;
        uVar7 = iVar4 - 0x37;
      }
    }
    base = local_28;
    if (uVar7 < local_28) {
LAB_00406807:
      uVar9 = (int)uVar7 >> 0x1f;
      bVar11 = false;
LAB_0040689a:
      nptr = nptr + 1;
      iVar4 = (int)*nptr;
      uVar10 = iVar4 - 0x30;
      if (9 < uVar10) {
        iVar5 = isupper(iVar4);
        if (iVar5 == 0) {
          iVar5 = islower(iVar4);
          if (iVar5 == 0) goto LAB_00406964;
          uVar10 = iVar4 - 0x57;
        }
        else {
          uVar10 = iVar4 - 0x37;
        }
      }
      if (local_28 <= uVar10) goto LAB_00406964;
      lVar12 = ___divdi3(0xffffffff,0x7fffffff,base,base >> 0x1f);
      uVar8 = (uint)((ulonglong)(lVar12 + 2) >> 0x20);
      if (uVar8 < uVar9 || uVar8 - uVar9 < (uint)((uint)(lVar12 + 2) < uVar7)) {
        bVar11 = true;
      }
      else {
        iVar4 = (base >> 0x1f) * uVar7;
        uVar2 = (ulonglong)uVar7;
        uVar8 = (uint)(uVar2 * (uint)base);
        uVar7 = uVar8 + uVar10;
        uVar9 = (int)(uVar2 * (uint)base >> 0x20) + iVar4 + base * uVar9 + ((int)uVar10 >> 0x1f) +
                (uint)CARRY4(uVar8,uVar10);
      }
      goto LAB_0040689a;
    }
  }
LAB_004068fb:
  uVar7 = 0;
  uVar9 = 0;
LAB_004068ff:
  return CONCAT44(uVar9,uVar7);
LAB_00406964:
  if (endptr != (char **)0x0) {
    *endptr = nptr;
  }
  if (cVar1 == '-') {
    if ((0x80000000 < uVar9 || 0x80000000 - uVar9 < (uint)(uVar7 != 0)) || (bVar11)) {
      piVar6 = __errno();
      uVar9 = 0x80000000;
      *piVar6 = 0x22;
      uVar7 = 0;
    }
    else {
      bVar11 = uVar7 != 0;
      uVar7 = -uVar7;
      uVar9 = -(uVar9 + bVar11);
    }
  }
  else if (((int)uVar9 < 0) || (bVar11)) {
    piVar6 = __errno();
    *piVar6 = 0x22;
    return 0x7fffffffffffffff;
  }
  goto LAB_004068ff;
}



// --- Function: strtoumax @ 00406a40 ---

/* WARNING: Unknown calling convention */

uintmax_t strtoumax(char *nptr,char **endptr,int base)

{
  char cVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  int *piVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  bool bVar11;
  ulonglong uVar12;
  uint local_28;
  
                    /* Unresolved local var: uintmax_t accum@[???]
                       Unresolved local var: uintmax_t next@[???]
                       Unresolved local var: int n@[???]
                       Unresolved local var: int minus@[???]
                       Unresolved local var: int toobig@[???] */
  if (endptr != (char **)0x0) {
    *endptr = nptr;
  }
  if ((base == 1) || (0x24 < (uint)base)) {
    piVar6 = __errno();
    *piVar6 = 0x21;
  }
  else {
    while( true ) {
      cVar1 = *nptr;
      iVar3 = isspace((int)cVar1);
      if (iVar3 == 0) break;
      nptr = nptr + 1;
    }
    cVar2 = cVar1;
    if (((int)cVar1 - 0x2bU & 0xfd) == 0) {
      cVar2 = nptr[1];
      nptr = nptr + 1;
    }
    if (base == 0) {
      base = 10;
      if (cVar2 != '0') goto LAB_00406ab8;
      if ((nptr[1] & 0xdfU) == 0x58) goto LAB_00406c40;
      local_28 = 8;
LAB_00406cc8:
      uVar8 = (uint)(char)(cVar2 + -0x30);
    }
    else {
      if ((base == 0x10) && (cVar2 == '0')) {
        if ((nptr[1] & 0xdfU) != 0x58) {
          local_28 = 0x10;
          uVar8 = 0;
          goto LAB_00406b07;
        }
LAB_00406c40:
        cVar2 = nptr[2];
        base = 0x10;
        nptr = nptr + 2;
      }
LAB_00406ab8:
      iVar3 = (int)cVar2;
      if (iVar3 - 0x30U < 10) {
        local_28 = base;
        goto LAB_00406cc8;
      }
      iVar4 = isupper(iVar3);
      if (iVar4 == 0) {
        iVar4 = islower(iVar3);
        if (iVar4 == 0) goto LAB_00406c0b;
        uVar8 = iVar3 - 0x57;
        local_28 = base;
      }
      else {
        local_28 = base;
        uVar8 = iVar3 - 0x37;
      }
    }
    base = local_28;
    if (uVar8 < local_28) {
LAB_00406b07:
      bVar11 = false;
      uVar10 = (int)uVar8 >> 0x1f;
LAB_00406ba6:
      uVar7 = uVar10;
      uVar9 = uVar8;
      nptr = nptr + 1;
      iVar3 = (int)*nptr;
      uVar10 = iVar3 - 0x30;
      if (9 < uVar10) {
        iVar4 = isupper(iVar3);
        if (iVar4 == 0) {
          iVar4 = islower(iVar3);
          if (iVar4 == 0) goto LAB_00406c74;
          uVar10 = iVar3 - 0x57;
        }
        else {
          uVar10 = iVar3 - 0x37;
        }
      }
      if (uVar10 < local_28) {
        uVar12 = ___udivdi3(0xffffffff,0xffffffff,base,base >> 0x1f);
        uVar8 = (uint)(uVar12 + 1 >> 0x20);
        if (uVar7 <= uVar8 && (uint)((uint)(uVar12 + 1) < uVar9) <= uVar8 - uVar7)
        goto code_r0x00406b72;
        goto LAB_00406c58;
      }
      goto LAB_00406c74;
    }
  }
LAB_00406c0b:
  uVar9 = 0;
  uVar7 = 0;
LAB_00406c0f:
  return CONCAT44(uVar7,uVar9);
LAB_00406c74:
  if (endptr != (char **)0x0) {
    *endptr = nptr;
  }
  if (bVar11) {
    piVar6 = __errno();
    uVar9 = 0xffffffff;
    uVar7 = 0xffffffff;
    *piVar6 = 0x22;
  }
  else if (cVar1 == '-') {
    bVar11 = uVar9 != 0;
    uVar9 = -uVar9;
    uVar7 = -(uVar7 + bVar11);
  }
  goto LAB_00406c0f;
code_r0x00406b72:
  uVar5 = (uint)((ulonglong)uVar9 * (ulonglong)(uint)base);
  uVar8 = uVar10 + uVar5;
  uVar10 = ((int)uVar10 >> 0x1f) +
           (int)((ulonglong)uVar9 * (ulonglong)(uint)base >> 0x20) +
           (base >> 0x1f) * uVar9 + base * uVar7 + (uint)CARRY4(uVar10,uVar5);
  if (uVar10 < uVar7 || uVar10 - uVar7 < (uint)(uVar8 < uVar9)) {
LAB_00406c58:
    bVar11 = true;
    uVar8 = uVar9;
    uVar10 = uVar7;
  }
  goto LAB_00406ba6;
}



// --- Function: __pformat_cvt @ 00406d10 ---

char * __fastcall __pformat_cvt(int mode,long_double val,int nd,int *dp,int *sign)

{
  float10 fVar1;
  long_double auVar2;
  int in_EAX;
  int be;
  char *pcVar3;
  uint uVar4;
  ushort uStack_34;
  int k;
  char *ep;
  __pformat_fpreg_t x;
  
  auVar2 = val;
                    /* Unresolved local var: uint e@[???] */
                    /* Unresolved local var: __pformat_fpreg_t x@[???] */
  x._0_2_ = val._0_2_;
  x._2_2_ = val._2_2_;
  x._4_2_ = val._4_2_;
  x._6_2_ = val._6_2_;
  x._8_2_ = val._8_2_;
                    /* Unresolved local var: wchar_t sw@[???] */
  fVar1 = (float10)0;
  uStack_34 = auVar2._8_2_;
  if (NAN((float10)val._0_10_)) {
    if ((float10)val._0_10_ == fVar1) {
      k = 4;
      be = 0;
      uVar4 = 0;
      goto LAB_00406d6c;
    }
    k = 3;
    be = 0;
  }
  else if ((float10)val._0_10_ != fVar1) {
    if ((float10)val._0_10_ == fVar1) {
      k = 2;
      be = -0x403d;
    }
    else {
      k = 1;
      be = (int)(short)((uStack_34 & 0x7fff) + 0xbfc2);
    }
  }
  else {
    k = 0;
    be = 0;
  }
  uVar4 = uStack_34 & 0x8000;
LAB_00406d6c:
  *dp = uVar4;
  pcVar3 = __gdtoa(&__pformat_cvt::fpi,be,&x.__pformat_fpreg_bits,&k,in_EAX,nd,(int *)mode,&ep);
  return pcVar3;
}



// --- Function: __pformat_putc @ 00406e00 ---

void __fastcall __pformat_putc(int c,__pformat_t *stream)

{
  int in_EAX;
  int iVar1;
  
  if (((stream->flags & 0x4000U) != 0) || (iVar1 = stream->count, iVar1 < stream->quota)) {
    if ((stream->flags & 0x2000U) != 0) {
      fputc(in_EAX,stream->dest);
      stream->count = stream->count + 1;
      return;
    }
    *(char *)((int)&stream->dest->_ptr + stream->count) = (char)in_EAX;
    iVar1 = stream->count;
  }
  stream->count = iVar1 + 1;
  return;
}



// --- Function: __pformat_wputchars @ 00406e60 ---

void __fastcall __pformat_wputchars(wchar_t *s,int count,__pformat_t *stream)

{
  char *pcVar1;
  wchar_t *in_EAX;
  size_t sVar2;
  int iVar3;
  int extraout_ECX;
  int extraout_ECX_00;
  int extraout_ECX_01;
  int extraout_ECX_02;
  int iVar4;
  char *pcVar5;
  char *pcVar6;
  bool bVar7;
  wchar_t *local_44;
  int local_40;
  mbstate_t state;
  char buf [16];
  
                    /* Unresolved local var: int len@[???] */
  wcrtomb(buf,L'\0',(mbstate_t *)&state);
  iVar3 = *(int *)(s + 6);
  iVar4 = iVar3;
  if (count <= iVar3) {
    iVar4 = count;
  }
  if (-1 < iVar3) {
    count = iVar4;
  }
  if (count < *(int *)(s + 4)) {
    iVar3 = *(int *)(s + 4) - count;
    *(int *)(s + 4) = iVar3;
    if ((*(byte *)((int)s + 5) & 4) == 0) {
      *(int *)(s + 4) = iVar3 + -1;
      iVar3 = extraout_ECX;
      do {
        __pformat_putc(iVar3,(__pformat_t *)s);
        iVar4 = *(int *)(s + 4);
        *(int *)(s + 4) = iVar4 + -1;
        iVar3 = extraout_ECX_02;
      } while (iVar4 != 0);
      local_44 = in_EAX;
      local_40 = count + -1;
      if (count < 1) goto LAB_00406f7c;
    }
    else {
      local_44 = in_EAX;
      local_40 = count + -1;
      if (count < 1) {
        *(int *)(s + 4) = *(int *)(s + 4) + -1;
        iVar3 = extraout_ECX;
        goto LAB_00406f70;
      }
    }
  }
  else {
    s[4] = L'\xffff';
    s[5] = L'\xffff';
    local_44 = in_EAX;
    local_40 = count + -1;
    if (count < 1) {
      s[4] = L'\xfffe';
      s[5] = L'\xffff';
      return;
    }
  }
  do {
    sVar2 = wcrtomb(buf,*local_44,(mbstate_t *)&state);
    iVar3 = extraout_ECX_00;
    if ((int)sVar2 < 1) break;
                    /* Unresolved local var: char * p@[???] */
    pcVar1 = buf + sVar2;
    pcVar5 = buf;
    do {
      while( true ) {
        pcVar6 = pcVar5 + 1;
        if (((*(uint *)(s + 2) & 0x4000) != 0) ||
           (iVar3 = *(int *)(s + 0x10), iVar3 < *(int *)(s + 0x12))) break;
LAB_00406ef9:
        *(int *)(s + 0x10) = iVar3 + 1;
        pcVar5 = pcVar6;
        if (pcVar6 == pcVar1) goto LAB_00406f3a;
      }
      if ((*(uint *)(s + 2) & 0x2000) == 0) {
        *(char *)((int)&(*(FILE **)s)->_ptr + *(int *)(s + 0x10)) = *pcVar5;
        iVar3 = *(int *)(s + 0x10);
        goto LAB_00406ef9;
      }
      fputc((int)*pcVar5,*(FILE **)s);
      *(int *)(s + 0x10) = *(int *)(s + 0x10) + 1;
      pcVar5 = pcVar6;
    } while (pcVar6 != pcVar1);
LAB_00406f3a:
    bVar7 = local_40 != 0;
    iVar3 = 0;
    local_44 = local_44 + 1;
    local_40 = local_40 + -1;
  } while (bVar7);
LAB_00406f7c:
  while (iVar4 = *(int *)(s + 4), *(int *)(s + 4) = iVar4 + -1, 0 < iVar4) {
LAB_00406f70:
    __pformat_putc(iVar3,(__pformat_t *)s);
    iVar3 = extraout_ECX_01;
  }
  return;
}



// --- Function: __pformat_putchars @ 00406fe0 ---

void __fastcall __pformat_putchars(char *s,int count,__pformat_t *stream)

{
  char *in_EAX;
  uint uVar1;
  int iVar2;
  char *c;
  char *extraout_ECX;
  int iVar3;
  char *pcVar4;
  
  iVar2 = *(int *)(s + 0xc);
  iVar3 = iVar2;
  if (count <= iVar2) {
    iVar3 = count;
  }
  if (-1 < iVar2) {
    count = iVar3;
  }
  pcVar4 = in_EAX;
  if (count < *(int *)(s + 8)) {
    iVar2 = *(int *)(s + 8) - count;
    *(int *)(s + 8) = iVar2;
    uVar1 = *(uint *)(s + 4);
    if ((uVar1 & 0x400) == 0) {
      *(int *)(s + 8) = iVar2 + -1;
      c = s;
      do {
        __pformat_putc((int)c,(__pformat_t *)s);
        iVar2 = *(int *)(s + 8);
        *(int *)(s + 8) = iVar2 + -1;
        c = extraout_ECX;
      } while (iVar2 != 0);
      if (count == 0) goto LAB_00407080;
      uVar1 = *(uint *)(s + 4);
    }
    else if (count == 0) {
      *(int *)(s + 8) = *(int *)(s + 8) + -1;
      goto LAB_00407090;
    }
  }
  else {
    s[8] = -1;
    s[9] = -1;
    s[10] = -1;
    s[0xb] = -1;
    if (count == 0) {
      s[8] = -2;
      s[9] = -1;
      s[10] = -1;
      s[0xb] = -1;
      return;
    }
    uVar1 = *(uint *)(s + 4);
  }
  while( true ) {
    if (((uVar1 & 0x4000) != 0) || (iVar2 = *(int *)(s + 0x20), iVar2 < *(int *)(s + 0x24))) {
      if ((uVar1 & 0x2000) == 0) {
        *(char *)((int)&(*(FILE **)s)->_ptr + *(int *)(s + 0x20)) = *pcVar4;
        iVar2 = *(int *)(s + 0x20);
      }
      else {
        fputc((int)*pcVar4,*(FILE **)s);
        iVar2 = *(int *)(s + 0x20);
      }
    }
    *(int *)(s + 0x20) = iVar2 + 1;
    if (in_EAX + (count - (int)(pcVar4 + 1)) == (char *)0x0) break;
    uVar1 = *(uint *)(s + 4);
    pcVar4 = pcVar4 + 1;
  }
LAB_00407080:
  while (iVar2 = *(int *)(s + 8), *(int *)(s + 8) = iVar2 + -1, 0 < iVar2) {
    uVar1 = *(uint *)(s + 4);
LAB_00407090:
    if (((uVar1 & 0x4000) != 0) || (iVar2 = *(int *)(s + 0x20), iVar2 < *(int *)(s + 0x24))) {
      if ((uVar1 & 0x2000) == 0) {
        *(undefined1 *)((int)&(*(FILE **)s)->_ptr + *(int *)(s + 0x20)) = 0x20;
        iVar2 = *(int *)(s + 0x20);
      }
      else {
        fputc(0x20,*(FILE **)s);
        iVar2 = *(int *)(s + 0x20);
      }
    }
    *(int *)(s + 0x20) = iVar2 + 1;
  }
  return;
}



// --- Function: __pformat_puts @ 00407130 ---

void __fastcall __pformat_puts(char *s,__pformat_t *stream)

{
  char *in_EAX;
  size_t count;
  int count_00;
  __pformat_t *in_stack_00000004;
  
  if (in_EAX == (char *)0x0) {
    in_EAX = "(null)";
  }
  if (-1 < stream->precision) {
    count = strnlen(in_EAX,stream->precision);
    __pformat_putchars((char *)stream,count,in_stack_00000004);
    return;
  }
  count_00 = strlen(in_EAX);
  __pformat_putchars((char *)stream,count_00,in_stack_00000004);
  return;
}



// --- Function: __pformat_emit_inf_or_nan @ 00407190 ---

void __fastcall __pformat_emit_inf_or_nan(int sign,char *value,__pformat_t *stream)

{
  uint uVar1;
  char cVar2;
  int in_EAX;
  int iVar3;
  char *pcVar4;
  __pformat_t *in_stack_ffffffd4;
  char buf [4];
  
                    /* Unresolved local var: int i@[???]
                       Unresolved local var: char * p@[???] */
  *(undefined4 *)(sign + 0xc) = 0xffffffff;
  uVar1 = *(uint *)(sign + 4);
  if (in_EAX == 0) {
    cVar2 = '+';
    if ((uVar1 & 0x100) == 0) {
      if ((uVar1 & 0x40) == 0) {
        pcVar4 = buf;
      }
      else {
        pcVar4 = buf + 1;
        buf[0] = ' ';
      }
      goto LAB_004071c9;
    }
  }
  else {
    cVar2 = '-';
  }
  pcVar4 = buf + 1;
  buf[0] = cVar2;
LAB_004071c9:
  iVar3 = 0;
  do {
    pcVar4[iVar3] = value[iVar3] & 0xdfU | (byte)uVar1 & 0x20;
    iVar3 = iVar3 + 1;
  } while (iVar3 != 3);
  __pformat_putchars((char *)sign,(int)(pcVar4 + (3 - (int)buf)),in_stack_ffffffd4);
  return;
}



// --- Function: __pformat_xint @ 00407220 ---

/* WARNING: Unable to track spacebase fully for stack */
/* WARNING: Type propagation algorithm not settling */

void __fastcall __pformat_xint(int fmt,__pformat_intarg_t value,__pformat_t *stream)

{
  uint uVar1;
  byte bVar2;
  int in_EAX;
  uint uVar3;
  int iVar4;
  byte bVar5;
  uint extraout_ECX;
  uint extraout_ECX_00;
  uint extraout_ECX_01;
  uint extraout_ECX_02;
  byte bVar6;
  undefined4 *puVar7;
  int *piVar8;
  int iVar9;
  byte *pbVar10;
  __pformat_t *p_Var11;
  byte *pbVar12;
  bool bVar13;
  undefined1 auStack_4c [16];
  uint local_3c;
  int local_38;
  undefined4 local_34;
  int local_30;
  byte *local_2c;
  byte local_25;
  uint local_24;
  byte *local_20;
  
                    /* Unresolved local var: int width@[???]
                       Unresolved local var: int shift@[???]
                       Unresolved local var: int bufflen@[???]
                       Unresolved local var: char * buf@[???]
                       Unresolved local var: char * p@[???]
                       Unresolved local var: int mask@[???] */
  local_30 = in_EAX;
  if (in_EAX == 0x6f) {
    local_34 = *(int *)(value.__pformat_long_t + 0xc);
    if ((*(uint *)(value.__pformat_long_t + 4) & 0x1000) != 0) {
      local_20 = (byte *)0x3;
      goto LAB_00407262;
    }
    local_38 = *(int *)(value.__pformat_long_t + 8);
    uVar3 = ___chkstk_ms();
    bVar6 = 7;
    piVar8 = (int *)(auStack_4c + -uVar3);
    local_20 = (byte *)0x3;
    local_2c = (byte *)((int)&local_34 + -uVar3 + 3 & 0xfffffff0);
    uVar3 = extraout_ECX_02;
LAB_00407386:
    pbVar10 = local_2c;
    puVar7 = piVar8;
    if (fmt == 0 && stream == (__pformat_t *)0x0) goto LAB_004072be;
LAB_00407390:
                    /* Unresolved local var: char * q@[???] */
    local_3c = uVar3;
    local_24 = CONCAT31(local_24._1_3_,bVar6);
    local_25 = (byte)local_30 & 0x20;
    pbVar12 = local_2c;
    do {
      pbVar10 = pbVar12 + 1;
      bVar2 = bVar6 & (byte)stream;
      bVar5 = bVar2 + 0x30;
      bVar2 = bVar2 + 0x37 | (byte)local_30 & 0x20;
      if (bVar5 < 0x3a) {
        bVar2 = bVar5;
      }
      uVar1 = fmt << 0x20 - ((byte)local_20 & 0x1f);
      *pbVar12 = bVar2;
      p_Var11 = (__pformat_t *)((uint)fmt >> ((byte)local_20 & 0x1f));
      fmt = (int)p_Var11;
      stream = (__pformat_t *)((uint)stream >> ((byte)local_20 & 0x1f) | uVar1);
      if (((uint)local_20 & 0x20) != 0) {
        fmt = 0;
        stream = p_Var11;
      }
      pbVar12 = pbVar10;
    } while ((__pformat_t *)fmt != (__pformat_t *)0x0 || stream != (__pformat_t *)0x0);
    uVar3 = local_3c;
    puVar7 = piVar8;
    if (pbVar10 == local_2c) goto LAB_004072be;
    if (local_34 < 1) {
      if (local_30 == 0x6f) goto LAB_004076e4;
      iVar4 = (int)pbVar10 - (int)local_2c;
      if (local_38 <= iVar4) {
LAB_0040765c:
        *(undefined4 *)(value.__pformat_long_t + 8) = 0xffffffff;
        local_20 = pbVar10;
        goto LAB_00407668;
      }
      goto LAB_00407586;
    }
    iVar4 = (int)pbVar10 - (int)local_2c;
    iVar9 = local_34 - iVar4;
    if (0 < iVar9) goto LAB_004072df;
    if (local_30 == 0x6f) {
      if ((uVar3 & 0x800) != 0) goto LAB_004076ed;
      if (iVar4 < local_38) goto LAB_00407586;
      *(undefined4 *)(value.__pformat_long_t + 8) = 0xffffffff;
      goto LAB_00407333;
    }
    if (local_38 <= iVar4) goto LAB_0040765c;
    iVar4 = local_38 - iVar4;
    *(int *)(value.__pformat_long_t + 8) = iVar4;
    if ((uVar3 & 0x800) == 0) goto LAB_00407438;
LAB_0040759c:
    iVar4 = iVar4 + -2;
    if (iVar4 < 1) {
      pbVar12[1] = 0x30;
      *pbVar12 = (byte)local_30;
      pbVar10 = pbVar12 + 2;
    }
    else {
      if ((-1 < local_34) || ((uVar3 & 0x600) != 0x200)) {
        pbVar12[1] = 0x30;
        pbVar10 = pbVar12 + 2;
        *pbVar12 = (byte)local_30;
        goto LAB_00407438;
      }
      local_24 = uVar3;
      *piVar8 = (int)pbVar12;
      piVar8[2] = iVar4;
      piVar8[1] = 0x30;
      local_20 = pbVar12;
      piVar8[-1] = 0x40777e;
      memset((void *)*piVar8,piVar8[1],piVar8[2]);
      bVar6 = (byte)(local_24 >> 8);
      local_20 = local_20 + iVar4;
LAB_00407606:
      iVar4 = -1;
      pbVar10 = local_20;
      if ((bVar6 & 8) != 0) {
        local_20[1] = 0x30;
        pbVar10 = local_20 + 2;
        *local_20 = (byte)local_30;
      }
    }
LAB_0040767f:
    if (pbVar10 <= local_2c) {
      return;
    }
    local_20 = (byte *)(iVar4 + -1);
  }
  else {
    local_34 = *(int *)(value.__pformat_long_t + 0xc);
    if ((*(uint *)(value.__pformat_long_t + 4) & 0x1000) == 0) {
      local_38 = *(int *)(value.__pformat_long_t + 8);
      uVar3 = ___chkstk_ms();
      bVar6 = 0xf;
      piVar8 = (int *)(auStack_4c + -uVar3);
      local_20 = (byte *)0x4;
      local_2c = (byte *)((int)&local_34 + -uVar3 + 3 & 0xfffffff0);
      uVar3 = extraout_ECX_00;
      goto LAB_00407386;
    }
    local_20 = (byte *)0x4;
LAB_00407262:
    local_38 = *(int *)(value.__pformat_long_t + 8);
    uVar3 = ___chkstk_ms();
    iVar4 = -uVar3;
    piVar8 = (int *)(auStack_4c + iVar4);
    local_2c = (byte *)((int)&local_34 + iVar4 + 3 & 0xfffffff0);
    bVar6 = (local_30 != 0x6f) * '\b' + 7;
    uVar3 = extraout_ECX;
    pbVar10 = local_2c;
    puVar7 = (undefined4 *)(auStack_4c + iVar4);
    if (fmt != 0 || stream != (__pformat_t *)0x0) goto LAB_00407390;
LAB_004072be:
    uVar3 = uVar3 & 0xfffff7ff;
    *(uint *)(value.__pformat_long_t + 4) = uVar3;
    iVar9 = local_34 - ((int)pbVar10 - (int)local_2c);
    piVar8 = puVar7;
    if (local_34 < 1) {
      pbVar12 = pbVar10;
      if (local_30 == 0x6f) {
LAB_004076e4:
        pbVar12 = pbVar10;
        if ((uVar3 & 0x800) != 0) {
LAB_004076ed:
          *pbVar10 = 0x30;
          pbVar12 = pbVar10 + 1;
        }
      }
    }
    else {
LAB_004072df:
      *piVar8 = (int)pbVar10;
      piVar8[2] = iVar9;
      piVar8[1] = 0x30;
      local_20 = pbVar10;
      piVar8[-1] = 0x4072f6;
      memset((void *)*piVar8,piVar8[1],piVar8[2]);
      pbVar12 = local_20 + iVar9;
      puVar7 = piVar8;
    }
    if ((pbVar12 == local_2c) && (local_34 != 0)) {
      pbVar10 = pbVar12 + 1;
      *pbVar12 = 0x30;
      iVar4 = (int)pbVar10 - (int)local_2c;
    }
    else {
      iVar4 = (int)pbVar12 - (int)local_2c;
      pbVar10 = pbVar12;
    }
    piVar8 = puVar7;
    if (iVar4 < local_38) {
      uVar3 = *(uint *)(value.__pformat_long_t + 4);
LAB_00407586:
      iVar4 = local_38 - iVar4;
      *(int *)(value.__pformat_long_t + 8) = iVar4;
      if ((local_30 != 0x6f) && (pbVar12 = pbVar10, (uVar3 & 0x800) != 0)) goto LAB_0040759c;
      if ((local_34 < 0) && ((uVar3 & 0x600) == 0x200)) {
        local_24 = uVar3;
        *piVar8 = (int)pbVar10;
        piVar8[2] = iVar4;
        piVar8[1] = 0x30;
        local_20 = pbVar10;
        piVar8[-1] = 0x4075f7;
        memset((void *)*piVar8,piVar8[1],piVar8[2]);
        bVar6 = (byte)(local_24 >> 8);
        local_20 = local_20 + iVar4;
        if (local_30 == 0x6f) goto LAB_0040767a;
        goto LAB_00407606;
      }
LAB_00407438:
      pbVar12 = (byte *)(iVar4 + -1);
      if ((uVar3 & 0x400) != 0) {
        if (pbVar10 <= local_2c) {
LAB_00407518:
          while( true ) {
            if (((uVar3 & 0x4000) != 0) ||
               (iVar4 = *(int *)(value.__pformat_long_t + 0x20),
               iVar4 < *(int *)(value.__pformat_long_t + 0x24))) {
              if ((uVar3 & 0x2000) == 0) {
                *(undefined1 *)
                 (*(int *)value.__pformat_ptr_t + *(int *)(value.__pformat_long_t + 0x20)) = 0x20;
                iVar4 = *(int *)(value.__pformat_long_t + 0x20);
              }
              else {
                piVar8[1] = *(int *)value.__pformat_ptr_t;
                *piVar8 = 0x20;
                piVar8[-1] = 0x40753c;
                fputc(*piVar8,(FILE *)piVar8[1]);
                iVar4 = *(int *)(value.__pformat_long_t + 0x20);
              }
            }
            *(int *)(value.__pformat_long_t + 0x20) = iVar4 + 1;
            if ((int)pbVar12 < 1) break;
            uVar3 = *(uint *)(value.__pformat_long_t + 4);
            pbVar12 = pbVar12 + -1;
          }
          return;
        }
        local_20 = pbVar12;
        local_24 = iVar4;
        pbVar12 = local_2c;
        goto LAB_004074a6;
      }
      do {
        *(undefined4 *)((int)piVar8 + -4) = 0x40745c;
        __pformat_putc(uVar3,value.__pformat_ptr_t);
        bVar13 = pbVar12 != (byte *)0x0;
        pbVar12 = pbVar12 + -1;
        uVar3 = extraout_ECX_01;
      } while (bVar13);
      local_20 = (byte *)0xfffffffe;
      iVar4 = -1;
      if (pbVar10 <= local_2c) {
        return;
      }
    }
    else {
      *(undefined4 *)(value.__pformat_long_t + 8) = 0xffffffff;
      if (local_30 != 0x6f) {
        uVar3 = *(uint *)(value.__pformat_long_t + 4);
        local_20 = pbVar10;
LAB_00407668:
        if ((uVar3 & 0x800) != 0) {
          local_20[1] = 0x30;
          *local_20 = (byte)local_30;
          local_20 = local_20 + 2;
        }
LAB_0040767a:
        iVar4 = -1;
        pbVar10 = local_20;
        goto LAB_0040767f;
      }
LAB_00407333:
      local_20 = (byte *)0xfffffffe;
      iVar4 = -1;
      if (pbVar10 <= local_2c) {
        return;
      }
    }
  }
  local_24 = iVar4;
  uVar3 = *(uint *)(value.__pformat_long_t + 4);
  pbVar12 = local_2c;
LAB_004074a6:
  do {
    pbVar10 = pbVar10 + -1;
    if (((uVar3 & 0x4000) == 0) &&
       (iVar4 = *(int *)(value.__pformat_long_t + 0x20),
       *(int *)(value.__pformat_long_t + 0x24) <= iVar4)) {
LAB_00407499:
      *(int *)(value.__pformat_long_t + 0x20) = iVar4 + 1;
    }
    else {
      bVar6 = *pbVar10;
      if ((uVar3 & 0x2000) == 0) {
        *(byte *)(*(int *)value.__pformat_ptr_t + *(int *)(value.__pformat_long_t + 0x20)) = bVar6;
        iVar4 = *(int *)(value.__pformat_long_t + 0x20);
        goto LAB_00407499;
      }
      piVar8[1] = *(int *)value.__pformat_ptr_t;
      *piVar8 = (int)(char)bVar6;
      piVar8[-1] = 0x4074cc;
      fputc(*piVar8,(FILE *)piVar8[1]);
      *(int *)(value.__pformat_long_t + 0x20) = *(int *)(value.__pformat_long_t + 0x20) + 1;
    }
    if (pbVar10 <= pbVar12) break;
    uVar3 = *(uint *)(value.__pformat_long_t + 4);
  } while( true );
  if ((int)local_24 < 1) {
    return;
  }
  uVar3 = *(uint *)(value.__pformat_long_t + 4);
  pbVar12 = local_20;
  goto LAB_00407518;
}



// --- Function: __pformat_int @ 00407790 ---

/* WARNING: Unable to track spacebase fully for stack */

void __fastcall __pformat_int(__pformat_intarg_t value,__pformat_t *stream)

{
  char cVar1;
  longlong lVar2;
  int iVar3;
  uint in_EAX;
  uint uVar4;
  char *pcVar5;
  int iVar6;
  int extraout_ECX;
  int extraout_ECX_00;
  int extraout_ECX_01;
  uint in_EDX;
  char *pcVar7;
  char *pcVar8;
  int iVar9;
  bool bVar10;
  int aiStack_60 [7];
  undefined1 uStack_41;
  int local_40;
  int local_3c;
  __pformat_t *local_38;
  uint local_34;
  char *local_30;
  uint local_2c;
  undefined4 local_28;
  uint local_24;
  uint local_20;
  
                    /* Unresolved local var: int32_t bufflen@[???]
                       Unresolved local var: char * buf@[???]
                       Unresolved local var: char * p@[???]
                       Unresolved local var: int precision@[???] */
  local_3c = stream->precision;
  local_34 = stream->flags;
  local_40 = stream->width;
  aiStack_60[0] = 0x4077e0;
  uVar4 = ___chkstk_ms();
  iVar3 = -uVar4;
  pcVar5 = (char *)((uint)(&uStack_41 + iVar3) & 0xfffffff0);
  local_30 = pcVar5;
  if ((local_34 & 0x80) == 0) {
LAB_00407807:
    local_24 = in_EAX;
    local_20 = in_EDX;
    if (in_EDX != 0 || in_EAX != 0) goto LAB_00407815;
    pcVar7 = local_30;
    iVar9 = local_3c;
    if (0 < local_3c) goto LAB_004078fe;
    bVar10 = true;
    iVar6 = extraout_ECX;
    pcVar5 = local_30;
LAB_0040791a:
    pcVar7 = pcVar5;
    if ((local_3c == 0) || (!bVar10)) goto LAB_00407929;
  }
  else {
    if (-1 < (int)in_EDX) {
      local_34 = local_34 & 0xffffff7f;
      stream->flags = local_34;
      goto LAB_00407807;
    }
    local_24 = -in_EAX;
    local_20 = -(in_EDX + (in_EAX != 0));
LAB_00407815:
    local_38 = stream;
    pcVar8 = pcVar5;
    while( true ) {
      local_28 = 0;
      local_2c = local_24 + local_20 + (uint)CARRY4(local_24,local_20);
      local_2c = local_2c -
                 (((uint)((ulonglong)local_2c * 0xcccccccd >> 0x20) & 0xfffffffc) + local_2c / 5);
      lVar2 = (ulonglong)(local_24 - local_2c) * 0xcccccccd;
      uVar4 = (int)((ulonglong)lVar2 >> 0x20) +
              (local_20 - (local_24 < local_2c)) * -0x33333333 + (local_24 - local_2c) * -0x33333334
      ;
      pcVar7 = pcVar8 + 1;
      *pcVar8 = ((byte)lVar2 & 1) * '\x05' + (char)local_2c + '0';
      if (local_20 == 0 && (uint)(9 < local_24) <= -local_20) break;
      if ((((pcVar5 != pcVar7) && ((local_34 & 0x1000) != 0)) && (stream->thousands_chr != L'\0'))
         && (((int)pcVar7 - (int)pcVar5 & 0x80000003U) == 3)) {
        *pcVar7 = ',';
        pcVar7 = pcVar8 + 2;
      }
      local_24 = (uint)lVar2 >> 1 | uVar4 * -0x80000000;
      local_20 = uVar4 >> 1;
      pcVar8 = pcVar7;
    }
    iVar6 = local_3c;
    if (local_3c < 1) {
LAB_00407914:
      bVar10 = local_30 == pcVar7;
      pcVar5 = pcVar7;
      goto LAB_0040791a;
    }
    iVar9 = local_3c - ((int)pcVar7 - (int)pcVar5);
    if (0 < iVar9) {
LAB_004078fe:
      *(char **)((int)aiStack_60 + iVar3 + 4) = pcVar7;
      pcVar7 = pcVar7 + iVar9;
      *(int *)((int)aiStack_60 + iVar3 + 0xc) = iVar9;
      *(undefined4 *)((int)aiStack_60 + iVar3 + 8) = 0x30;
      *(undefined4 *)((int)aiStack_60 + iVar3) = 0x407914;
      memset(*(void **)((int)aiStack_60 + iVar3 + 4),*(int *)((int)aiStack_60 + iVar3 + 8),
             *(size_t *)((int)aiStack_60 + iVar3 + 0xc));
      iVar6 = extraout_ECX_00;
      goto LAB_00407914;
    }
    if (pcVar5 != pcVar7) goto LAB_00407929;
  }
  *pcVar5 = '0';
  pcVar7 = pcVar5 + 1;
LAB_00407929:
  if (0 < local_40) {
    iVar9 = local_40 - ((int)pcVar7 - (int)local_30);
    stream->width = iVar9;
    if (0 < iVar9) {
      if ((local_34 & 0x1c0) != 0) {
        stream->width = iVar9 + -1;
      }
      if ((local_3c < 0) && ((local_34 & 0x600) == 0x200)) {
        iVar9 = stream->width;
        stream->width = iVar9 + -1;
        if (0 < iVar9) {
          *(char **)((int)aiStack_60 + iVar3 + 4) = pcVar7;
          pcVar7 = pcVar7 + iVar9;
          *(int *)((int)aiStack_60 + iVar3 + 0xc) = iVar9;
          *(undefined4 *)((int)aiStack_60 + iVar3 + 8) = 0x30;
          *(undefined4 *)((int)aiStack_60 + iVar3) = 0x407b03;
          memset(*(void **)((int)aiStack_60 + iVar3 + 4),*(int *)((int)aiStack_60 + iVar3 + 8),
                 *(size_t *)((int)aiStack_60 + iVar3 + 0xc));
          stream->width = -1;
        }
      }
      else if (((local_34 & 0x400) == 0) &&
              (iVar9 = stream->width, stream->width = iVar9 + -1, 0 < iVar9)) {
        do {
          *(undefined4 *)((int)aiStack_60 + iVar3) = 0x407b34;
          __pformat_putc(iVar6,stream);
          iVar9 = stream->width;
          stream->width = iVar9 + -1;
          iVar6 = extraout_ECX_01;
        } while (0 < iVar9);
        local_34 = stream->flags;
      }
    }
  }
  pcVar5 = local_30;
  if ((local_34 & 0x80) == 0) {
    if ((local_34 & 0x100) == 0) {
      if ((local_34 & 0x40) != 0) {
        *pcVar7 = ' ';
        pcVar7 = pcVar7 + 1;
      }
    }
    else {
      *pcVar7 = '+';
      pcVar7 = pcVar7 + 1;
    }
  }
  else {
    *pcVar7 = '-';
    pcVar7 = pcVar7 + 1;
  }
  uVar4 = local_34;
  if (pcVar7 <= local_30) {
LAB_004079d1:
    iVar9 = stream->width;
    while( true ) {
      iVar6 = iVar9 + -1;
      stream->width = iVar6;
      if (iVar9 < 1) break;
      if (((stream->flags & 0x4000U) != 0) || (iVar9 = stream->count, iVar9 < stream->quota)) {
        if ((stream->flags & 0x2000U) == 0) {
          *(undefined1 *)((int)stream->dest + stream->count) = 0x20;
          iVar9 = stream->count;
          iVar6 = stream->width;
        }
        else {
          *(void **)((int)aiStack_60 + iVar3 + 8) = stream->dest;
          *(undefined4 *)((int)aiStack_60 + iVar3 + 4) = 0x20;
          *(undefined4 *)((int)aiStack_60 + iVar3) = 0x407a26;
          fputc(*(int *)((int)aiStack_60 + iVar3 + 4),*(FILE **)((int)aiStack_60 + iVar3 + 8));
          iVar9 = stream->count;
          iVar6 = stream->width;
        }
      }
      stream->count = iVar9 + 1;
      iVar9 = iVar6;
    }
    return;
  }
  do {
    pcVar7 = pcVar7 + -1;
    if (((uVar4 & 0x4000) == 0) && (iVar9 = stream->count, stream->quota <= iVar9)) {
LAB_00407991:
      stream->count = iVar9 + 1;
    }
    else {
      cVar1 = *pcVar7;
      if ((uVar4 & 0x2000) == 0) {
        *(char *)((int)stream->dest + stream->count) = cVar1;
        iVar9 = stream->count;
        goto LAB_00407991;
      }
      *(void **)((int)aiStack_60 + iVar3 + 8) = stream->dest;
      *(int *)((int)aiStack_60 + iVar3 + 4) = (int)cVar1;
      *(undefined4 *)((int)aiStack_60 + iVar3) = 0x4079c4;
      fputc(*(int *)((int)aiStack_60 + iVar3 + 4),*(FILE **)((int)aiStack_60 + iVar3 + 8));
      stream->count = stream->count + 1;
    }
    if (pcVar5 == pcVar7) goto LAB_004079d1;
    uVar4 = stream->flags;
  } while( true );
}



// --- Function: __pformat_emit_radix_point @ 00407b80 ---

/* WARNING: Unable to track spacebase fully for stack */

void __fastcall __pformat_emit_radix_point(__pformat_t *stream)

{
  char *pcVar1;
  void *pvVar2;
  int iVar3;
  __pformat_t *in_EAX;
  uint uVar4;
  size_t sVar5;
  undefined4 *puVar6;
  int c;
  __pformat_t *extraout_ECX;
  undefined4 extraout_EDX;
  int iVar7;
  char *pcVar8;
  char *pcVar9;
  undefined4 uStackY_50;
  char acStack_3c [12];
  undefined1 *local_30;
  wchar_t rpchr;
  mbstate_t state;
  
                    /* Unresolved local var: uint anon_var_0@[???] */
  if (in_EAX->rplen == -3) {
                    /* Unresolved local var: int len@[???] */
    state._Wchar = 0;
    state._Byte = L'\0';
    state._State = L'\0';
    uStackY_50 = 0x407c76;
    puVar6 = (undefined4 *)localeconv();
    uStackY_50 = 0x407c93;
    sVar5 = mbrtowc(&rpchr,(char *)*puVar6,0x10,(mbstate_t *)&state);
    if ((int)sVar5 < 1) {
      rpchr = in_EAX->rpchr;
    }
    else {
      in_EAX->rpchr = rpchr;
    }
    in_EAX->rplen = sVar5;
    stream = extraout_ECX;
  }
  else {
    rpchr = in_EAX->rpchr;
  }
  if (rpchr == L'\0') {
    uStackY_50 = 0x407c54;
    __pformat_putc((int)stream,in_EAX);
    return;
  }
                    /* Unresolved local var: int len@[???]
                       Unresolved local var: char[60133] buf@[???] */
  uStackY_50 = 0x407bb6;
  local_30 = &stack0xffffffb4;
  uVar4 = ___chkstk_ms();
  iVar3 = -uVar4;
  state._Wchar = 0;
  pcVar1 = acStack_3c + iVar3;
  state._Byte = L'\0';
  state._State = L'\0';
  *(mbstate_t **)(&stack0xffffffbc + iVar3) = &state;
  *(undefined4 *)(&stack0xffffffb8 + iVar3) = extraout_EDX;
  *(char **)(&stack0xffffffb4 + iVar3) = pcVar1;
  *(undefined4 *)((int)&uStackY_50 + iVar3) = 0x407bdd;
  sVar5 = wcrtomb(*(char **)(&stack0xffffffb4 + iVar3),*(wchar_t *)(&stack0xffffffb8 + iVar3),
                  *(mbstate_t **)(&stack0xffffffbc + iVar3));
  if ((int)sVar5 < 1) {
    *(undefined4 *)((int)&uStackY_50 + iVar3) = 0x407cbc;
    __pformat_putc(c,in_EAX);
  }
  else {
                    /* Unresolved local var: char * p@[???] */
    pcVar8 = pcVar1;
    do {
      while( true ) {
        pcVar9 = pcVar8 + 1;
        if (((in_EAX->flags & 0x4000U) != 0) || (iVar7 = in_EAX->count, iVar7 < in_EAX->quota))
        break;
LAB_00407bf9:
        in_EAX->count = iVar7 + 1;
        pcVar8 = pcVar9;
        if (pcVar9 == pcVar1 + sVar5) {
          return;
        }
      }
      pvVar2 = in_EAX->dest;
      if ((in_EAX->flags & 0x2000U) == 0) {
        *(char *)((int)pvVar2 + in_EAX->count) = *pcVar8;
        iVar7 = in_EAX->count;
        goto LAB_00407bf9;
      }
      *(int *)(&stack0xffffffb4 + iVar3) = (int)*pcVar8;
      *(void **)(&stack0xffffffb8 + iVar3) = pvVar2;
      *(undefined4 *)((int)&uStackY_50 + iVar3) = 0x407c2d;
      fputc(*(int *)(&stack0xffffffb4 + iVar3),*(FILE **)(&stack0xffffffb8 + iVar3));
      in_EAX->count = in_EAX->count + 1;
      pcVar8 = pcVar9;
    } while (pcVar9 != pcVar1 + sVar5);
  }
  return;
}



// --- Function: __pformat_emit_float @ 00407cd0 ---

void __fastcall __pformat_emit_float(int sign,char *value,int len,__pformat_t *stream)

{
  undefined1 *puVar1;
  int in_EAX;
  int iVar2;
  uint uVar3;
  __pformat_t *p_Var4;
  __pformat_t *stream_00;
  __pformat_t *extraout_ECX;
  __pformat_t *extraout_ECX_00;
  __pformat_t *extraout_ECX_01;
  __pformat_t *extraout_ECX_02;
  __pformat_t *extraout_ECX_03;
  __pformat_t *extraout_ECX_04;
  __pformat_t *extraout_ECX_05;
  __pformat_t *extraout_ECX_06;
  __pformat_t *extraout_ECX_07;
  __pformat_t *extraout_ECX_08;
  __pformat_t *extraout_ECX_09;
  __pformat_t *in_stack_ffffffd4;
  
  p_Var4 = *(__pformat_t **)(len + 8);
  if (sign < 1) {
    if ((int)p_Var4 < 1) {
      if ((p_Var4 == (__pformat_t *)0x0) && (p_Var4 = *(__pformat_t **)(len + 0xc), (int)p_Var4 < 0)
         ) {
        p_Var4 = (__pformat_t *)-(int)p_Var4;
        *(__pformat_t **)(len + 8) = p_Var4;
LAB_00407f56:
        if ((*(uint *)(len + 4) & 0x800) != 0) goto LAB_00407d0c;
        if ((0 < sign) && ((*(uint *)(len + 4) & 0x1000) != 0)) goto LAB_00407f73;
        goto LAB_00407d24;
      }
    }
    else {
      iVar2 = *(int *)(len + 0xc);
      p_Var4 = (__pformat_t *)((int)&p_Var4[-1].expmin + 3);
      if (iVar2 < (int)p_Var4) goto LAB_00407cff;
    }
    *(undefined4 *)(len + 8) = 0xffffffff;
    if (in_EAX == 0) goto LAB_00407d75;
LAB_00407e50:
    __pformat_putc((int)p_Var4,(__pformat_t *)len);
    p_Var4 = extraout_ECX_00;
  }
  else {
    if ((int)p_Var4 < sign) {
      *(undefined4 *)(len + 8) = 0xffffffff;
      if (((*(byte *)(len + 5) & 0x10) != 0) && (*(short *)(len + 0x1c) != 0)) {
                    /* Unresolved local var: int cths@[???] */
        p_Var4 = (__pformat_t *)0xffffffff;
        uVar3 = (sign + 2U) / 3;
        if (uVar3 != 1) {
LAB_00407ff7:
          iVar2 = (uVar3 - 1) - (int)p_Var4;
          do {
            if ((int)p_Var4 < 1) goto LAB_00407d69;
            p_Var4 = (__pformat_t *)((int)&p_Var4[-1].expmin + 3);
            *(__pformat_t **)(len + 8) = p_Var4;
          } while ((undefined1 *)(iVar2 + (int)p_Var4) != (undefined1 *)0x0);
          goto LAB_00407d20;
        }
      }
LAB_00407d69:
      if (in_EAX != 0) goto LAB_00407e50;
LAB_00407d75:
      uVar3 = *(uint *)(len + 4);
    }
    else {
      iVar2 = *(int *)(len + 0xc);
      p_Var4 = (__pformat_t *)((int)p_Var4 - sign);
      if (iVar2 < (int)p_Var4) {
LAB_00407cff:
        p_Var4 = (__pformat_t *)((int)p_Var4 - iVar2);
        *(__pformat_t **)(len + 8) = p_Var4;
        if (iVar2 < 1) goto LAB_00407f56;
LAB_00407d0c:
        p_Var4 = (__pformat_t *)((int)&p_Var4[-1].expmin + 3);
        *(__pformat_t **)(len + 8) = p_Var4;
        if ((0 < sign) && ((*(byte *)(len + 5) & 0x10) != 0)) {
LAB_00407f73:
          if (*(short *)(len + 0x1c) != 0) goto LAB_00408057;
        }
      }
      else {
        *(undefined4 *)(len + 8) = 0xffffffff;
        if (((*(byte *)(len + 5) & 0x10) == 0) || (*(short *)(len + 0x1c) == 0)) goto LAB_00407d69;
        p_Var4 = (__pformat_t *)0xffffffff;
LAB_00408057:
        uVar3 = (sign + 2) / 3;
        if (uVar3 != 1) goto LAB_00407ff7;
      }
LAB_00407d20:
      if ((int)p_Var4 < 1) goto LAB_00407d69;
LAB_00407d24:
      if (in_EAX != 0) {
        puVar1 = (undefined1 *)((int)&p_Var4[-1].expmin + 3);
        *(undefined1 **)(len + 8) = puVar1;
        if ((puVar1 == (undefined1 *)0x0) || ((*(uint *)(len + 4) & 0x600) != 0)) goto LAB_00407e50;
LAB_00407f13:
        p_Var4 = (__pformat_t *)((int)&p_Var4[-1].expmin + 2);
LAB_00407f16:
        *(__pformat_t **)(len + 8) = p_Var4;
        do {
          __pformat_putc((int)p_Var4,(__pformat_t *)len);
          iVar2 = *(int *)(len + 8);
          *(int *)(len + 8) = iVar2 + -1;
          p_Var4 = extraout_ECX_06;
        } while (0 < iVar2);
        goto LAB_00407d69;
      }
      uVar3 = *(uint *)(len + 4);
      if ((uVar3 & 0x1c0) == 0) {
        p_Var4 = (__pformat_t *)((int)&p_Var4[-1].expmin + 3);
        if ((uVar3 & 0x600) == 0) goto LAB_00407f16;
      }
      else {
        puVar1 = (undefined1 *)((int)&p_Var4[-1].expmin + 3);
        *(undefined1 **)(len + 8) = puVar1;
        if ((puVar1 != (undefined1 *)0x0) && ((uVar3 & 0x600) == 0)) goto LAB_00407f13;
      }
    }
    if ((uVar3 & 0x100) == 0) {
      if ((uVar3 & 0x40) != 0) {
        __pformat_putc((int)p_Var4,(__pformat_t *)len);
        p_Var4 = extraout_ECX_09;
      }
    }
    else {
      __pformat_putc((int)p_Var4,(__pformat_t *)len);
      p_Var4 = extraout_ECX_07;
    }
  }
  if ((0 < *(int *)(len + 8)) && ((*(uint *)(len + 4) & 0x600) == 0x200)) {
    *(int *)(len + 8) = *(int *)(len + 8) + -1;
    do {
      __pformat_putc((int)p_Var4,(__pformat_t *)len);
      iVar2 = *(int *)(len + 8);
      *(int *)(len + 8) = iVar2 + -1;
      p_Var4 = extraout_ECX_08;
    } while (0 < iVar2);
  }
  if (sign < 1) {
    __pformat_putc((int)p_Var4,(__pformat_t *)len);
    iVar2 = *(int *)(len + 0xc);
    p_Var4 = extraout_ECX_03;
    if ((0 < iVar2) || ((*(byte *)(len + 5) & 8) != 0)) goto LAB_00407ec7;
    if (sign == 0) goto LAB_00407e11;
  }
  else {
    while( true ) {
      if (*value != '\0') {
        value = value + 1;
      }
      __pformat_putc((int)p_Var4,(__pformat_t *)len);
      sign = sign + -1;
      if (sign == 0) break;
      p_Var4 = stream_00;
      if ((((*(byte *)(len + 5) & 0x10) != 0) && (*(short *)(len + 0x1c) != 0)) &&
         ((uint)(sign * -0x55555555) < 0x55555556)) {
        __pformat_wputchars((wchar_t *)len,1,in_stack_ffffffd4);
        p_Var4 = extraout_ECX;
      }
    }
    iVar2 = *(int *)(len + 0xc);
    if (0 < iVar2) {
      __pformat_emit_radix_point(stream_00);
      p_Var4 = extraout_ECX_01;
      goto LAB_00407e91;
    }
    sign = 0;
    p_Var4 = stream_00;
    if ((*(byte *)(len + 5) & 8) == 0) {
LAB_00407e11:
      *(int *)(len + 0xc) = iVar2 + -1;
      return;
    }
LAB_00407ec7:
    __pformat_emit_radix_point(p_Var4);
    p_Var4 = extraout_ECX_04;
    if (sign == 0) goto LAB_00407e91;
    iVar2 = *(int *)(len + 0xc);
  }
  *(int *)(len + 0xc) = iVar2 + sign;
  do {
    __pformat_putc((int)p_Var4,(__pformat_t *)len);
    sign = sign + 1;
    p_Var4 = extraout_ECX_05;
  } while (sign != 0);
LAB_00407e91:
  while (iVar2 = *(int *)(len + 0xc), *(int *)(len + 0xc) = iVar2 + -1, 0 < iVar2) {
    if (*value != '\0') {
      value = value + 1;
    }
    __pformat_putc((int)p_Var4,(__pformat_t *)len);
    p_Var4 = extraout_ECX_02;
  }
  return;
}



// --- Function: __pformat_emit_efloat @ 004080a0 ---

void __fastcall __pformat_emit_efloat(int sign,char *value,int e,__pformat_t *stream)

{
  __pformat_intarg_t value_00;
  int c;
  int iVar1;
  int iVar2;
  undefined8 in_stack_0000000c;
  __pformat_t *in_stack_ffffffc8;
  
                    /* Unresolved local var: int exp_width@[???]
                       Unresolved local var: __pformat_intarg_t exponent@[???] */
  iVar1 = 1;
  iVar2 = sign + -1;
  while (iVar2 = iVar2 / 10, iVar2 != 0) {
    iVar1 = iVar1 + 1;
  }
  iVar2 = *(int *)(e + 0x28);
  if (iVar2 == -1) {
    *(undefined4 *)(e + 0x28) = 2;
    iVar2 = 2;
  }
  if (iVar2 < iVar1) {
    iVar2 = iVar1;
  }
  iVar1 = *(int *)(e + 8) - (iVar2 + 2);
  if (*(int *)(e + 8) <= iVar2 + 2) {
    iVar1 = -1;
  }
  *(int *)(e + 8) = iVar1;
  __pformat_emit_float(1,value,e,in_stack_ffffffc8);
  *(undefined4 *)(e + 0xc) = *(undefined4 *)(e + 0x28);
  *(uint *)(e + 4) = *(uint *)(e + 4) | 0x1c0;
  __pformat_putc(c,(__pformat_t *)e);
  *(int *)(e + 8) = *(int *)(e + 8) + iVar2 + 1;
  value_00.__pformat_llong_t._4_4_ = stream;
  value_00.__pformat_long_t = e;
  value_00._8_8_ = in_stack_0000000c;
  __pformat_int(value_00,(__pformat_t *)e);
  return;
}



// --- Function: __pformat_efloat @ 00408180 ---

void __cdecl __pformat_efloat(long_double x,__pformat_t *stream)

{
  undefined1 val [12];
  int in_EAX;
  char *value;
  int nd;
  __pformat_t *stream_00;
  __pformat_t *stream_01;
  undefined2 in_stack_ffffffde;
  int *in_stack_ffffffe4;
  int sign;
  int intlen;
  
                    /* Unresolved local var: char * value@[???] */
  if (*(int *)(in_EAX + 0xc) < 0) {
    *(undefined4 *)(in_EAX + 0xc) = 6;
    nd = 7;
  }
  else {
    nd = *(int *)(in_EAX + 0xc) + 1;
  }
  stream_00 = x._0_4_;
  stream_01 = x._4_4_;
  val._10_2_ = in_stack_ffffffde;
  val._0_10_ = x._0_10_;
  value = __pformat_cvt((int)&intlen,val,nd,&sign,in_stack_ffffffe4);
  if (intlen != -0x8000) {
    __pformat_emit_efloat(intlen,value,in_EAX,stream_01);
    __freedtoa(value);
    return;
  }
  __pformat_emit_inf_or_nan(in_EAX,value,stream_00);
  __freedtoa(value);
  return;
}



// --- Function: __pformat_float @ 00408210 ---

void __cdecl __pformat_float(long_double x,__pformat_t *stream)

{
  undefined1 val [12];
  undefined4 *in_EAX;
  char *value;
  int iVar1;
  int iVar2;
  __pformat_t *stream_00;
  __pformat_t *stream_01;
  undefined2 in_stack_ffffffde;
  int *in_stack_ffffffe4;
  int sign;
  int intlen;
  
                    /* Unresolved local var: char * value@[???] */
  iVar2 = in_EAX[3];
  if (iVar2 < 0) {
    in_EAX[3] = 6;
    iVar2 = 6;
  }
  stream_00 = x._0_4_;
  stream_01 = x._4_4_;
  val._10_2_ = in_stack_ffffffde;
  val._0_10_ = x._0_10_;
  value = __pformat_cvt((int)&intlen,val,iVar2,&sign,in_stack_ffffffe4);
  if (intlen == -0x8000) {
    __pformat_emit_inf_or_nan((int)in_EAX,value,stream_00);
  }
  else {
    __pformat_emit_float(intlen,value,(int)in_EAX,stream_01);
    iVar2 = in_EAX[2];
    while( true ) {
      iVar1 = iVar2 + -1;
      in_EAX[2] = iVar1;
      if (iVar2 < 1) break;
      if (((in_EAX[1] & 0x4000) != 0) || (iVar2 = in_EAX[8], iVar2 < (int)in_EAX[9])) {
        if ((in_EAX[1] & 0x2000) == 0) {
          *(undefined1 *)((int)&((FILE *)*in_EAX)->_ptr + in_EAX[8]) = 0x20;
          iVar2 = in_EAX[8];
          iVar1 = in_EAX[2];
        }
        else {
          fputc(0x20,(FILE *)*in_EAX);
          iVar2 = in_EAX[8];
          iVar1 = in_EAX[2];
        }
      }
      in_EAX[8] = iVar2 + 1;
      iVar2 = iVar1;
    }
  }
  __freedtoa(value);
  return;
}



// --- Function: __pformat_gfloat @ 004082e0 ---

void __cdecl __pformat_gfloat(long_double x,__pformat_t *stream)

{
  int iVar1;
  undefined1 val [12];
  __pformat_t *in_EAX;
  char *value;
  uint uVar2;
  int iVar3;
  int extraout_ECX;
  int extraout_ECX_00;
  __pformat_t *stream_00;
  __pformat_t *stream_01;
  undefined2 in_stack_ffffffde;
  int *in_stack_ffffffe4;
  int sign;
  int intlen;
  
                    /* Unresolved local var: char * value@[???] */
  iVar3 = in_EAX->precision;
  if (iVar3 < 0) {
    in_EAX->precision = 6;
    iVar3 = 6;
  }
  else if (iVar3 == 0) {
    in_EAX->precision = 1;
    iVar3 = 1;
  }
  stream_00 = x._0_4_;
  stream_01 = x._4_4_;
  val._10_2_ = in_stack_ffffffde;
  val._0_10_ = x._0_10_;
  value = __pformat_cvt((int)&intlen,val,iVar3,&sign,in_stack_ffffffe4);
  if (intlen != -0x8000) {
    uVar2 = in_EAX->flags & 0x800;
    if ((-4 < intlen) && (intlen <= in_EAX->precision)) {
      if (uVar2 == 0) {
        iVar3 = strlen(value);
        iVar3 = iVar3 - intlen;
        in_EAX->precision = iVar3;
        if ((iVar3 < 0) && (0 < in_EAX->width)) {
          in_EAX->width = iVar3 + in_EAX->width;
        }
      }
      else {
        in_EAX->precision = in_EAX->precision - intlen;
      }
      __pformat_emit_float(intlen,value,(int)in_EAX,stream_01);
      iVar3 = extraout_ECX;
      while (iVar1 = in_EAX->width, in_EAX->width = iVar1 + -1, 0 < iVar1) {
        __pformat_putc(iVar3,in_EAX);
        iVar3 = extraout_ECX_00;
      }
      __freedtoa(value);
      return;
    }
    if (uVar2 == 0) {
      iVar3 = strlen(value);
    }
    else {
      iVar3 = in_EAX->precision;
    }
    in_EAX->precision = iVar3 + -1;
    __pformat_emit_efloat(intlen,value,(int)in_EAX,stream_01);
    __freedtoa(value);
    return;
  }
  __pformat_emit_inf_or_nan((int)in_EAX,value,stream_00);
  __freedtoa(value);
  return;
}



// --- Function: __pformat_emit_xfloat @ 00408450 ---

void __fastcall __pformat_emit_xfloat(__pformat_fpreg_t value,__pformat_t *stream)

{
  char *pcVar1;
  uint uVar2;
  uint in_EAX;
  int iVar3;
  int iVar4;
  byte bVar5;
  byte bVar6;
  __pformat_t *extraout_ECX;
  int c;
  __pformat_t *extraout_ECX_00;
  __pformat_t *extraout_ECX_01;
  __pformat_t *p_Var7;
  __pformat_t *extraout_ECX_02;
  uint uVar8;
  __pformat_t *extraout_ECX_03;
  __pformat_t *extraout_ECX_04;
  __pformat_t *extraout_ECX_05;
  __pformat_t *extraout_ECX_06;
  __pformat_t *extraout_ECX_07;
  __pformat_t *extraout_ECX_08;
  uint in_EDX;
  uint uVar9;
  int iVar10;
  char *pcVar11;
  uint uVar12;
  uint uVar13;
  int iVar14;
  __pformat_t *in_stack_ffffffa4;
  char *local_58;
  uint local_54;
  int local_50;
  short local_44;
  wchar_t wcs;
  char buf [24];
  
                    /* Unresolved local var: char * p@[???]
                       Unresolved local var: __pformat_intarg_t exponent@[???]
                       Unresolved local var: short exp_width@[???] */
  uVar2 = *(uint *)(value.__pformat_fpreg_bits + 0xc);
  if (((short)stream == 0) && (in_EAX == 0 && in_EDX == 0)) {
    if (uVar2 < 0xf) {
      local_44 = 0;
LAB_004086c0:
      uVar8 = (0xe - uVar2) * 4;
      bVar5 = (byte)uVar8;
      bVar6 = bVar5 & 0x1f;
      uVar12 = 4 << (bVar5 & 0x1f);
      uVar13 = uVar12;
      uVar9 = 0 << bVar6 | 4U >> 0x20 - bVar6;
      if ((uVar8 & 0x20) != 0) {
        uVar13 = 0;
        uVar9 = uVar12;
      }
      uVar8 = in_EAX >> 1 | in_EDX << 0x1f;
      uVar12 = uVar8 + uVar13;
      uVar9 = (in_EDX >> 1) + uVar9 + (uint)CARRY4(uVar8,uVar13);
      uVar13 = (0xf - uVar2) * 4;
      bVar6 = (byte)uVar13;
      if ((int)uVar9 < 0) {
        local_44 = local_44 + 4;
        uVar8 = (uVar9 >> 3) >> (bVar6 & 0x1f);
        in_EAX = (uVar12 >> 3 | uVar9 * 0x20000000) >> (bVar6 & 0x1f) |
                 (uVar9 >> 3) << 0x20 - (bVar6 & 0x1f);
        in_EDX = uVar8;
        if ((uVar13 & 0x20) != 0) {
          in_EDX = 0;
          in_EAX = uVar8;
        }
      }
      else {
        uVar9 = uVar9 * 2 | uVar12 >> 0x1f;
        uVar8 = uVar9 >> (bVar6 & 0x1f);
        in_EDX = uVar8;
        in_EAX = uVar12 * 2 >> (bVar6 & 0x1f) | uVar9 << 0x20 - (bVar6 & 0x1f);
        if ((uVar13 & 0x20) != 0) {
          in_EDX = 0;
          in_EAX = uVar8;
        }
        if ((in_EDX == 0 && in_EAX == 0) && (uVar2 == 0)) {
          local_54 = *(uint *)(value.__pformat_fpreg_bits + 4);
          stream = (__pformat_t *)0x3c;
          goto LAB_00408736;
        }
      }
      iVar14 = uVar2 + 1;
    }
    else {
      if ((int)uVar2 < 1) {
        local_54 = *(uint *)(value.__pformat_fpreg_bits + 4);
        local_44 = 0;
        goto LAB_00408736;
      }
      iVar14 = 0x10;
      in_EDX = 0;
      local_44 = 0;
      in_EAX = 0;
    }
LAB_0040849d:
    local_54 = *(uint *)(value.__pformat_fpreg_bits + 4);
                    /* Unresolved local var: uint c@[???] */
    pcVar11 = buf;
    do {
      stream = (__pformat_t *)(in_EAX & 0xf);
      if (iVar14 == 1) {
        if (((buf < pcVar11) || ((local_54 & 0x800) != 0)) ||
           (0 < *(int *)(value.__pformat_fpreg_bits + 0xc))) {
          *pcVar11 = '.';
          pcVar11 = pcVar11 + 1;
          goto LAB_004084dd;
        }
        if (stream == (__pformat_t *)0x0) {
          if (*(int *)(value.__pformat_fpreg_bits + 0xc) == 0) {
            *pcVar11 = '0';
            pcVar11 = pcVar11 + 1;
          }
          break;
        }
LAB_004087a0:
        if (stream < (__pformat_t *)0xa) {
LAB_004084f6:
          stream = (__pformat_t *)&stream[1].flags;
        }
        else {
          stream = (__pformat_t *)(uint)(byte)((char)stream + 0x37U | (byte)local_54 & 0x20);
        }
        *pcVar11 = (char)stream;
        pcVar11 = pcVar11 + 1;
      }
      else {
        if (0 < *(int *)(value.__pformat_fpreg_bits + 0xc)) {
          *(int *)(value.__pformat_fpreg_bits + 0xc) =
               *(int *)(value.__pformat_fpreg_bits + 0xc) + -1;
        }
LAB_004084dd:
        if (stream != (__pformat_t *)0x0) goto LAB_004087a0;
        if ((buf < pcVar11) || (-1 < *(int *)(value.__pformat_fpreg_bits + 0xc))) goto LAB_004084f6;
      }
      in_EAX = in_EAX >> 4 | in_EDX << 0x1c;
      in_EDX = in_EDX >> 4;
      iVar14 = iVar14 + -1;
    } while (iVar14 != 0);
    if (pcVar11 == buf) {
      if (*(int *)(value.__pformat_fpreg_bits + 0xc) < 1) goto LAB_00408736;
      goto LAB_00408744;
    }
  }
  else {
    local_44 = (short)stream + -3;
    if (uVar2 < 0xf) goto LAB_004086c0;
                    /* Unresolved local var: int i@[???] */
    iVar14 = 0x10;
    stream = (__pformat_t *)((int)local_44 >> 0x1f);
    if ((in_EDX != 0 || in_EAX != 0) || (0 < (int)uVar2)) goto LAB_0040849d;
    local_54 = *(uint *)(value.__pformat_fpreg_bits + 4);
LAB_00408736:
    local_58 = buf;
    if ((local_54 & 0x800) != 0) {
LAB_00408744:
      buf[0] = '.';
      local_58 = buf + 1;
    }
    *local_58 = '0';
    pcVar11 = local_58 + 1;
  }
  local_58 = buf;
  iVar14 = *(int *)(value.__pformat_fpreg_bits + 8);
                    /* Unresolved local var: int min_width@[???]
                       Unresolved local var: int exponent2@[???] */
  local_50 = 2;
  if (0 < iVar14) {
    iVar3 = (int)pcVar11 - (int)local_58;
    if (0 < *(int *)(value.__pformat_fpreg_bits + 0xc)) {
      iVar3 = ((int)pcVar11 - (int)local_58) + *(int *)(value.__pformat_fpreg_bits + 0xc);
    }
    iVar4 = (iVar3 + 6) - (uint)((local_54 & 0x1c0) == 0);
    iVar3 = (int)local_44 / 10;
    iVar10 = iVar4;
    if (iVar3 != 0) {
      do {
        iVar10 = iVar10 + 1;
        iVar3 = iVar3 / 10;
      } while (iVar3 != 0);
      local_44 = (short)iVar4;
      local_50 = (int)(short)(((short)iVar10 - local_44) + 2);
      iVar4 = iVar10;
    }
    stream = (__pformat_t *)0x0;
    if (iVar4 < iVar14) {
      iVar14 = iVar14 - iVar4;
      if ((local_54 & 0x600) == 0) {
        *(int *)(value.__pformat_fpreg_bits + 8) = iVar14 + -1;
        do {
          __pformat_putc((int)stream,(__pformat_t *)value.__pformat_fpreg_bits);
          iVar14 = *(int *)(value.__pformat_fpreg_bits + 8);
          *(int *)(value.__pformat_fpreg_bits + 8) = iVar14 + -1;
          stream = extraout_ECX;
        } while (0 < iVar14);
        local_54 = *(uint *)(value.__pformat_fpreg_bits + 4);
        goto LAB_004085f0;
      }
    }
    else {
      iVar14 = -1;
    }
    *(int *)(value.__pformat_fpreg_bits + 8) = iVar14;
  }
LAB_004085f0:
  if ((local_54 & 0x80) == 0) {
    if ((local_54 & 0x100) == 0) {
      if ((local_54 & 0x40) != 0) {
        __pformat_putc((int)stream,(__pformat_t *)value.__pformat_fpreg_bits);
        stream = extraout_ECX_08;
      }
    }
    else {
      __pformat_putc((int)stream,(__pformat_t *)value.__pformat_fpreg_bits);
      stream = extraout_ECX_07;
    }
  }
  else {
    __pformat_putc((int)stream,(__pformat_t *)value.__pformat_fpreg_bits);
    stream = extraout_ECX_06;
  }
  __pformat_putc((int)stream,(__pformat_t *)value.__pformat_fpreg_bits);
  __pformat_putc(c,(__pformat_t *)value.__pformat_fpreg_bits);
  p_Var7 = extraout_ECX_00;
  if ((0 < *(int *)(value.__pformat_fpreg_bits + 8)) &&
     ((*(byte *)(value.__pformat_fpreg_bits + 5) & 2) != 0)) {
    *(int *)(value.__pformat_fpreg_bits + 8) = *(int *)(value.__pformat_fpreg_bits + 8) + -1;
    do {
      __pformat_putc((int)p_Var7,(__pformat_t *)value.__pformat_fpreg_bits);
      iVar14 = *(int *)(value.__pformat_fpreg_bits + 8);
      *(int *)(value.__pformat_fpreg_bits + 8) = iVar14 + -1;
      p_Var7 = extraout_ECX_01;
    } while (0 < iVar14);
  }
  if (local_58 < pcVar11) {
    do {
      pcVar1 = pcVar11 + -1;
      pcVar11 = pcVar11 + -1;
      if (*pcVar1 == '.') {
        __pformat_emit_radix_point(p_Var7);
        p_Var7 = extraout_ECX_04;
      }
      else if (*pcVar1 == ',') {
        if (*(short *)(value.__pformat_fpreg_bits + 0x1c) != 0) {
          __pformat_wputchars((wchar_t *)value.__pformat_fpreg_bits,1,in_stack_ffffffa4);
          p_Var7 = extraout_ECX_05;
        }
      }
      else {
        __pformat_putc((int)p_Var7,(__pformat_t *)value.__pformat_fpreg_bits);
        p_Var7 = extraout_ECX_02;
      }
    } while (pcVar11 != local_58);
  }
  while (iVar14 = *(int *)(value.__pformat_fpreg_bits + 0xc),
        *(int *)(value.__pformat_fpreg_bits + 0xc) = iVar14 + -1, 0 < iVar14) {
    __pformat_putc((int)p_Var7,(__pformat_t *)value.__pformat_fpreg_bits);
    p_Var7 = extraout_ECX_03;
  }
  __pformat_putc((int)p_Var7,(__pformat_t *)value.__pformat_fpreg_bits);
  *(int *)(value.__pformat_fpreg_bits + 8) = *(int *)(value.__pformat_fpreg_bits + 8) + local_50;
  *(uint *)(value.__pformat_fpreg_bits + 4) = *(uint *)(value.__pformat_fpreg_bits + 4) | 0x1c0;
  __pformat_int((__pformat_intarg_t)value,(__pformat_t *)value.__pformat_fpreg_bits);
  return;
}



// --- Function: __rv_alloc_D2A @ 004094e0 ---

/* WARNING: Unknown calling convention */

char * __rv_alloc_D2A(int i)

{
  int iVar1;
  __Bigint *p_Var2;
  __Bigint *k;
  
                    /* Unresolved local var: int j@[???]
                       Unresolved local var: int k@[???]
                       Unresolved local var: int * r@[???] */
  k = (__Bigint *)0x0;
  if (0x13 < i) {
    iVar1 = 4;
    do {
      iVar1 = iVar1 * 2;
      k = (__Bigint *)((int)&k->next + 1);
    } while (iVar1 + 0xf < i);
  }
  p_Var2 = __Balloc_D2A((int)k);
  p_Var2->next = k;
  return (char *)&p_Var2->k;
}



// --- Function: __nrv_alloc_D2A @ 00409520 ---

/* WARNING: Unknown calling convention */

char * __nrv_alloc_D2A(char *s,char **rve,int n)

{
  char cVar1;
  int iVar2;
  __Bigint *p_Var3;
  int *piVar4;
  __Bigint *k;
  
                    /* Unresolved local var: char * rv@[???]
                       Unresolved local var: char * t@[???] */
                    /* Unresolved local var: int j@[???]
                       Unresolved local var: int k@[???]
                       Unresolved local var: int * r@[???] */
  if (n < 0x14) {
    k = (__Bigint *)0x0;
  }
  else {
    iVar2 = 4;
    k = (__Bigint *)0x0;
    do {
      iVar2 = iVar2 * 2;
      k = (__Bigint *)((int)&k->next + 1);
    } while (iVar2 + 0xf < n);
  }
  p_Var3 = __Balloc_D2A((int)k);
  p_Var3->next = k;
  cVar1 = *s;
  *(char *)&p_Var3->k = cVar1;
  piVar4 = &p_Var3->k;
  while (cVar1 != '\0') {
    s = s + 1;
    cVar1 = *s;
    piVar4 = (int *)((int)piVar4 + 1);
    *(char *)piVar4 = cVar1;
  }
  if (rve != (char **)0x0) {
    *rve = (char *)piVar4;
  }
  return (char *)&p_Var3->k;
}



// --- Function: __freedtoa @ 004095a0 ---

/* WARNING: Unknown calling convention */

void __freedtoa(char *s)

{
                    /* Unresolved local var: __Bigint * b@[???] */
  *(undefined4 *)s = *(undefined4 *)(s + -4);
  *(int *)(s + 4) = 1 << ((byte)*(undefined4 *)(s + -4) & 0x1f);
  __Bfree_D2A((__Bigint *)(s + -4));
  return;
}



// --- Function: __quorem_D2A @ 004095c0 ---

/* WARNING: Unknown calling convention */

int __quorem_D2A(__Bigint *b,__Bigint *S)

{
  ULong *pUVar1;
  uint uVar2;
  longlong lVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  uint uVar7;
  ULong *pUVar8;
  ULong *pUVar9;
  ULong *pUVar10;
  ULong *pUVar11;
  ULong *pUVar12;
  uint local_54;
  uint local_44;
  int local_30;
  ULong *pUVar13;
  
                    /* Unresolved local var: int n@[???]
                       Unresolved local var: ULong * bx@[???]
                       Unresolved local var: ULong * bxe@[???]
                       Unresolved local var: ULong q@[???]
                       Unresolved local var: ULong * sx@[???]
                       Unresolved local var: ULong * sxe@[???]
                       Unresolved local var: ulonglong borrow@[???]
                       Unresolved local var: ulonglong carry@[???]
                       Unresolved local var: ulonglong y@[???]
                       Unresolved local var: ulonglong ys@[???] */
  iVar6 = S->wds;
  uVar4 = 0;
  if (iVar6 <= b->wds) {
    pUVar8 = b->x;
    pUVar9 = S->x;
    local_30 = iVar6 + -1;
    pUVar1 = pUVar9 + local_30;
    pUVar11 = pUVar8 + local_30;
    uVar4 = *pUVar11 / (*pUVar1 + 1);
    if (*pUVar1 + 1 <= *pUVar11) {
      local_44 = 0;
      local_54 = 0;
      pUVar10 = pUVar8;
      pUVar12 = pUVar9;
      do {
        pUVar13 = pUVar12 + 1;
        uVar2 = *pUVar10;
        lVar3 = (ulonglong)uVar4 * (ulonglong)*pUVar12 + (ulonglong)local_44;
        uVar5 = (uint)lVar3;
        local_44 = (uint)((ulonglong)lVar3 >> 0x20);
        uVar7 = uVar2 - uVar5;
        *pUVar10 = uVar7 - local_54;
        local_54 = -(uint)(uVar7 < local_54) - (uint)(uVar2 < uVar5) & 1;
        pUVar10 = pUVar10 + 1;
        pUVar12 = pUVar13;
      } while (pUVar13 <= pUVar1);
      if (*pUVar11 == 0) {
        if (pUVar8 < pUVar11 + -1) {
          do {
            if (pUVar11[local_30 - iVar6] != 0) break;
            local_30 = local_30 + -1;
          } while ((iVar6 + -2) - ((uint)((int)pUVar11 + (-0x19 - (int)b)) >> 2) != local_30);
        }
        b->wds = local_30;
      }
    }
    iVar6 = __cmp_D2A(b,S);
    if (-1 < iVar6) {
      local_54 = 0;
      pUVar11 = pUVar8;
      do {
        uVar2 = *pUVar9;
        pUVar9 = pUVar9 + 1;
        uVar5 = *pUVar11 - uVar2;
        uVar7 = uVar5 - local_54;
        local_54 = -(uint)(uVar5 < local_54) - (uint)(*pUVar11 < uVar2) & 1;
        *pUVar11 = uVar7;
        pUVar11 = pUVar11 + 1;
      } while (pUVar9 <= pUVar1);
      pUVar9 = pUVar8 + local_30;
      if (*pUVar9 == 0) {
        if (pUVar8 < pUVar9 + -1) {
          iVar6 = local_30 + -1;
          do {
            if (b->x[local_30 + -1] != 0) break;
            local_30 = local_30 + -1;
          } while (local_30 != iVar6 - ((uint)((int)pUVar9 + (-0x19 - (int)b)) >> 2));
        }
        b->wds = local_30;
      }
      uVar4 = uVar4 + 1;
    }
  }
  return uVar4;
}



// --- Function: __gdtoa @ 004097e0 ---

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* WARNING: Unknown calling convention */

char * __gdtoa(FPI *fpi,int be,ULong *bits,int *kindp,int mode,int ndigits,int *decpt,char **rve)

{
  bool bVar1;
  bool bVar2;
  double dVar3;
  bool bVar4;
  undefined4 uVar5;
  uint uVar6;
  int iVar7;
  __Bigint *b;
  ULong *pUVar8;
  int iVar9;
  __Bigint *p_Var10;
  int iVar11;
  __Bigint *p_Var12;
  ULong UVar13;
  char cVar14;
  int iVar15;
  int iVar16;
  uint uVar17;
  int iVar18;
  ULong *pUVar19;
  char *pcVar20;
  char *pcVar21;
  char *pcVar22;
  uint uVar23;
  int iVar24;
  double dVar25;
  uint local_a0;
  __Bigint *local_98;
  char *local_94;
  char local_90;
  uint local_88;
  undefined8 local_84;
  uint local_6c;
  uint local_68;
  int local_64;
  char *local_60;
  int local_5c;
  uint local_58;
  int local_50;
  undefined8 local_4c;
  uint local_40;
  double local_3c;
  uint local_34;
  int i;
  
                    /* Unresolved local var: int bbits@[???]
                       Unresolved local var: int b2@[???]
                       Unresolved local var: int b5@[???]
                       Unresolved local var: int be0@[???]
                       Unresolved local var: int dig@[???]
                       Unresolved local var: int ieps@[???]
                       Unresolved local var: int ilim@[???]
                       Unresolved local var: int ilim0@[???]
                       Unresolved local var: int ilim1@[???]
                       Unresolved local var: int inex@[???]
                       Unresolved local var: int j@[???]
                       Unresolved local var: int j2@[???]
                       Unresolved local var: int k@[???]
                       Unresolved local var: int k0@[???]
                       Unresolved local var: int k_check@[???]
                       Unresolved local var: int kind@[???]
                       Unresolved local var: int leftright@[???]
                       Unresolved local var: int m2@[???]
                       Unresolved local var: int m5@[???]
                       Unresolved local var: int nbits@[???]
                       Unresolved local var: int rdir@[???]
                       Unresolved local var: int s2@[???]
                       Unresolved local var: int s5@[???]
                       Unresolved local var: int spec_case@[???]
                       Unresolved local var: int try_quick@[???]
                       Unresolved local var: long L@[???]
                       Unresolved local var: __Bigint * b@[???]
                       Unresolved local var: __Bigint * b1@[???]
                       Unresolved local var: __Bigint * delta@[???]
                       Unresolved local var: __Bigint * mlo@[???]
                       Unresolved local var: __Bigint * mhi@[???]
                       Unresolved local var: __Bigint * mhi1@[???]
                       Unresolved local var: __Bigint * S@[???]
                       Unresolved local var: double d2@[???]
                       Unresolved local var: double ds@[???]
                       Unresolved local var: char * s@[???]
                       Unresolved local var: char * s0@[???]
                       Unresolved local var: _dbl_union d@[???]
                       Unresolved local var: _dbl_union eps@[???] */
  local_a0 = mode;
  local_94 = (char *)ndigits;
  uVar23 = *kindp;
  *kindp = uVar23 & 0xffffffcf;
  uVar6 = uVar23 & 7;
  if (uVar6 == 3) {
    *decpt = -0x8000;
    pcVar20 = __nrv_alloc_D2A("Infinity",rve,8);
    return pcVar20;
  }
  if ((uVar23 & 4) != 0) {
    if (uVar6 != 4) {
      return (char *)0x0;
    }
    *decpt = -0x8000;
    pcVar20 = __nrv_alloc_D2A("NaN",rve,3);
    return pcVar20;
  }
  if (uVar6 != 0) {
    iVar11 = fpi->nbits;
                    /* Unresolved local var: int i@[???]
                       Unresolved local var: int k@[???]
                       Unresolved local var: __Bigint * b@[???]
                       Unresolved local var: ULong * be@[???]
                       Unresolved local var: ULong * x@[???]
                       Unresolved local var: ULong * x0@[???] */
    iVar18 = 0;
    iVar7 = 0x20;
    if (0x20 < iVar11) {
      do {
        iVar7 = iVar7 * 2;
        iVar18 = iVar18 + 1;
      } while (iVar7 < iVar11);
    }
    iVar7 = iVar11 + -1 >> 5;
    b = __Balloc_D2A(iVar18);
    pUVar8 = bits;
    pUVar19 = b->x;
    do {
      UVar13 = *pUVar8;
      pUVar8 = pUVar8 + 1;
      *pUVar19 = UVar13;
      pUVar19 = pUVar19 + 1;
    } while (pUVar8 <= bits + iVar7);
    iVar18 = iVar7 * 4 + 4;
    if ((int)(bits + iVar7) + 1U < (int)bits + 1U) {
      iVar18 = 4;
    }
    iVar7 = iVar18 >> 2;
LAB_004098f0:
    iVar18 = iVar7 + -1;
    if (b->x[iVar7 + -1] == 0) goto LAB_004098e8;
    uVar6 = 0x1f;
    if (b->x[iVar7 + -1] != 0) {
      for (; b->x[iVar7 + -1] >> uVar6 == 0; uVar6 = uVar6 - 1) {
      }
    }
    b->wds = iVar7;
    iVar7 = iVar7 * 0x20 - (uVar6 ^ 0x1f);
    goto LAB_0040990f;
  }
LAB_00409ae8:
  *decpt = 1;
  pcVar20 = __nrv_alloc_D2A("0",rve,1);
  return pcVar20;
LAB_004098e8:
  iVar7 = iVar18;
  if (iVar18 == 0) goto LAB_00409b60;
  goto LAB_004098f0;
LAB_0040ab96:
  while( true ) {
    iVar11 = __cmp_D2A((__Bigint *)local_84,local_98);
    pcVar20 = local_94 + 1;
    if (iVar11 < 1) break;
    *local_94 = (char)local_a0;
    p_Var12 = __multadd_D2A(local_98,10,0);
    if (p_Var10 == local_98) {
      p_Var10 = p_Var12;
    }
    b = __multadd_D2A(b,10,0);
    iVar11 = __quorem_D2A(b,(__Bigint *)local_84);
    local_98 = p_Var12;
    local_94 = pcVar20;
    local_a0 = iVar11 + 0x30;
  }
  if (local_a0 == 0x39) {
LAB_0040ad9e:
    *local_94 = '9';
    pcVar21 = pcVar20;
    goto LAB_0040a9a0;
  }
  local_88 = 0x20;
  uVar23 = local_a0 + 1;
LAB_0040abd3:
  *local_94 = (char)uVar23;
LAB_0040a630:
  __Bfree_D2A((__Bigint *)local_84);
  pcVar22 = local_60;
  if (local_98 == (__Bigint *)0x0) goto LAB_0040a06d;
  if ((p_Var10 != (__Bigint *)0x0) && (p_Var10 != local_98)) {
    __Bfree_D2A(p_Var10);
  }
  goto LAB_0040a065;
code_r0x00409e4e:
  cVar14 = (char)uVar17 + '\x01';
LAB_00409e55:
  *pcVar20 = cVar14;
  local_88 = 0x20;
  local_68 = local_34 + 1;
  pcVar22 = local_60;
  pcVar20 = pcVar21;
  goto LAB_0040a06d;
LAB_00409b60:
  b->wds = 0;
  iVar7 = 0;
LAB_0040990f:
  i = __trailz_D2A(b);
  local_64 = be;
  if (i != 0) {
    __rshift_D2A(b,i);
    local_64 = be + i;
    iVar7 = iVar7 - i;
  }
  if (b->wds == 0) {
    __Bfree_D2A(b);
    goto LAB_00409ae8;
  }
  dVar25 = __b2d_D2A(b,&i);
  local_84._4_4_ = (uint)((ulonglong)dVar25 >> 0x20);
  iVar15 = local_64 + iVar7;
  uVar6 = local_84._4_4_ & 0xfffff;
  iVar16 = iVar15 + -1;
  local_84 = (double)((ulonglong)dVar25 & 0xfffffffffffff | 0x3ff0000000000000);
  iVar18 = 1 - iVar15;
  if (-1 < iVar16) {
    iVar18 = iVar16;
  }
  dVar3 = (double)iVar16 * _DAT_00411820 +
          (local_84 - (double)_DAT_00411808) * _DAT_00411810 + _DAT_00411818;
  if (0 < iVar18 + -0x435) {
    dVar3 = (double)(iVar18 + -0x435) * _DAT_00411828 + dVar3;
  }
  local_6c = (uint)ROUND(dVar3);
  if ((dVar3 < 0.0) && ((double)(int)local_6c != dVar3)) {
    local_6c = local_6c - 1;
  }
  iVar18 = iVar16 * 0x100000 + (uVar6 | 0x3ff00000);
  local_84._0_4_ = (__Bigint *)((ulonglong)dVar25 & 0xfffffffffffff);
  uVar5 = (__Bigint *)local_84;
  local_84 = (double)CONCAT44(iVar18,(__Bigint *)local_84);
  dVar25 = local_84;
  iVar16 = iVar7 - iVar16;
  local_68 = iVar16 + -1;
  if (local_6c < 0x17) {
    if (local_84 < __tens_D2A[local_6c]) {
      local_6c = local_6c - 1;
      bVar4 = false;
      goto LAB_00409ba0;
    }
    bVar4 = false;
    local_5c = 0;
    if (iVar16 < 1) {
      local_68 = 0;
      local_5c = 1 - iVar16;
    }
LAB_00409a78:
    local_50 = 0;
    local_68 = local_68 + local_6c;
    local_58 = local_6c;
  }
  else {
    bVar4 = true;
LAB_00409ba0:
    local_58 = local_6c;
    local_5c = 0;
    if ((int)local_68 < 0) {
      local_68 = 0;
      local_5c = 1 - iVar16;
    }
    if (-1 < (int)local_6c) goto LAB_00409a78;
    local_5c = local_5c - local_6c;
    local_6c = 0;
    local_50 = -local_58;
  }
  local_88 = 0;
  iVar16 = local_50;
  iVar24 = local_5c;
  if ((uint)mode < 10) {
    if (mode < 6) {
      bVar1 = iVar15 + 0x3fdU < 0x7f8;
      if (mode == 4) {
LAB_0040a981:
        bVar2 = true;
      }
      else {
        if (mode == 5) {
LAB_0040a800:
          bVar2 = true;
          goto LAB_00409f70;
        }
        if (mode != 2) {
          if (mode == 3) {
            bVar2 = false;
            goto LAB_00409f70;
          }
          goto LAB_00409e98;
        }
        bVar2 = false;
      }
LAB_00409c40:
      local_94 = (char *)0x1;
      i = (int)local_94;
      local_40 = (uint)local_94;
      uVar6 = (uint)local_94;
      if (0 < ndigits) {
        i = ndigits;
        local_94 = (char *)ndigits;
        local_40 = ndigits;
        uVar6 = ndigits;
      }
    }
    else {
      local_a0 = mode + -4;
      bVar1 = false;
      if (local_a0 == 4) goto LAB_0040a981;
      if (local_a0 == 5) goto LAB_0040a800;
      bVar2 = false;
      if (local_a0 == 2) goto LAB_00409c40;
      local_a0 = 3;
LAB_00409f70:
      local_40 = local_58 + ndigits;
      uVar6 = local_40 + 1;
      i = 1;
      if (0 < (int)uVar6) {
        i = uVar6;
      }
    }
    local_60 = __rv_alloc_D2A(i);
    iVar15 = fpi->rounding + -1;
    if (iVar15 != 0) {
LAB_00409c7f:
      iVar9 = 2;
      if (-1 < iVar15) {
        iVar9 = iVar15;
      }
      iVar15 = iVar9;
      if ((uVar23 & 8) != 0) {
        iVar15 = 3 - iVar9;
        goto LAB_00409ca7;
      }
LAB_0040a120:
      if (local_64 < 0) {
LAB_0040a12c:
        if (bVar2) goto LAB_0040a138;
LAB_0040a440:
        bVar1 = false;
        local_98 = (__Bigint *)0x0;
        goto LAB_0040a1c6;
      }
LAB_00409fe0:
      if (fpi->int_max < (int)local_58) goto LAB_0040a12c;
LAB_00409ff1:
      local_84 = (double)CONCAT44(iVar18,uVar5);
      dVar25 = __tens_D2A[local_58];
      if ((-1 < (int)local_94) || (0 < (int)uVar6)) {
        i = 1;
        uVar23 = (uint)ROUND(local_84 / dVar25);
        local_a0._0_1_ = (char)uVar23;
        *local_60 = (char)local_a0 + '0';
        local_68 = local_58 + 1;
        pcVar21 = local_60;
        for (local_84 = local_84 - (double)(int)uVar23 * dVar25; pcVar21 = pcVar21 + 1,
            pcVar22 = local_60, pcVar20 = pcVar21, local_84 != 0.0;
            local_84 = local_84 * dVar3 - (double)(int)uVar23 * dVar25) {
          if (i == uVar6) {
            if (iVar15 == 0) {
              uVar17 = (uint)(byte)pcVar21[-1];
              if (dVar25 < local_84 + local_84) {
                local_34 = local_58;
                goto LAB_00409e46;
              }
              local_34 = local_58;
              if (local_84 + local_84 == dVar25) {
                if ((uVar23 & 1) != 0) goto LAB_00409e46;
                local_88 = 0x10;
              }
              else {
                local_88 = 0x10;
              }
              goto LAB_0040ae60;
            }
            if (iVar15 == 1) {
              local_34 = local_58;
              uVar17 = (uint)(byte)pcVar21[-1];
              goto LAB_00409e46;
            }
            local_88 = 0x10;
            break;
          }
          dVar3 = (double)_DAT_0041183c;
          i = i + 1;
          uVar23 = (uint)ROUND((local_84 * dVar3) / dVar25);
          local_a0._0_1_ = (char)uVar23;
          *pcVar21 = (char)local_a0 + '0';
        }
        goto LAB_0040a06d;
      }
      if ((uVar6 == 0) && (dVar25 * (double)(float)DAT_00411848 < local_84)) {
        local_68 = local_58 + 2;
        local_84._0_4_ = (__Bigint *)0x0;
        local_98 = (__Bigint *)0x0;
        goto LAB_0040a045;
      }
LAB_0040a328:
      local_84._0_4_ = (__Bigint *)0x0;
      local_98 = (__Bigint *)0x0;
      goto LAB_0040a332;
    }
LAB_00409ca7:
    bVar1 = (bool)(uVar6 < 0xf & bVar1);
    if ((!bVar1) || (local_58 != 0 || iVar15 != 0)) goto LAB_0040a120;
    i = 0;
    if ((bVar4) && (local_84 < 1.0)) {
      if (uVar6 == 0) {
        dVar3 = local_84 + local_84 + (double)_DAT_00411844;
        local_84._4_4_ = (uint)((ulonglong)dVar3 >> 0x20);
        local_4c = (double)CONCAT44(local_84._4_4_ + -0x3400000,SUB84(dVar3,0));
        goto LAB_0040a0d0;
      }
      if (0 < (int)local_40) {
        local_34 = 0xffffffff;
        local_3c = local_84 * (double)_DAT_0041183c;
        dVar25 = local_3c * (double)_DAT_00411840 + (double)_DAT_00411844;
        local_4c._4_4_ = (int)((ulonglong)dVar25 >> 0x20);
        local_4c = (double)CONCAT44(local_4c._4_4_ + -0x3400000,SUB84(dVar25,0));
        uVar23 = local_40;
        goto LAB_00409d43;
      }
LAB_0040a100:
      iVar15 = 0;
      goto LAB_0040a120;
    }
    dVar3 = local_84 + local_84 + (double)_DAT_00411844;
    local_4c._4_4_ = (int)((ulonglong)dVar3 >> 0x20);
    local_4c = (double)CONCAT44(local_4c._4_4_ + -0x3400000,SUB84(dVar3,0));
    if (uVar6 != 0) {
      local_34 = 0;
      local_3c = local_84;
      uVar23 = uVar6;
LAB_00409d43:
      if (bVar2) {
        pcVar20 = local_60 + 1;
        local_4c = (double)DAT_00411848._4_4_ / *(double *)(&DAT_00411878 + uVar23 * 8) - local_4c;
        local_84._0_1_ = (char)(int)ROUND(local_3c);
        local_3c = local_3c - (double)(int)ROUND(local_3c);
        *local_60 = (char)local_84 + '0';
        pcVar21 = pcVar20;
        if (local_4c <= local_3c) {
          do {
            if ((double)_DAT_00411838 - local_3c < local_4c) {
              uVar17 = (uint)(byte)pcVar21[-1];
              goto LAB_00409e46;
            }
            i = i + 1;
            if ((int)uVar23 <= i) goto LAB_0040a100;
            pcVar20 = pcVar21 + 1;
            local_4c = local_4c * (double)_DAT_0041183c;
            local_3c = (double)_DAT_0041183c * local_3c;
            iVar15 = (int)ROUND(local_3c);
            local_84._0_1_ = (char)iVar15;
            local_3c = local_3c - (double)iVar15;
            *pcVar21 = (char)local_84 + '0';
            pcVar21 = pcVar20;
          } while (local_4c <= local_3c);
        }
        local_88 = (uint)NAN(local_3c);
        if (local_3c != 0.0) {
          local_88 = 1;
        }
        local_88 = local_88 << 4;
        local_68 = local_34 + 1;
        pcVar22 = local_60;
        goto LAB_0040a06d;
      }
      local_4c = *(double *)(&DAT_00411878 + uVar23 * 8) * local_4c;
      i = 1;
      pcVar20 = local_60;
      dVar25 = local_3c;
      bVar2 = false;
      while( true ) {
        iVar11 = (int)ROUND(dVar25);
        if (iVar11 != 0) {
          dVar25 = dVar25 - (double)iVar11;
          bVar2 = bVar1;
        }
        pcVar21 = pcVar20 + 1;
        uVar17 = iVar11 + 0x30;
        *pcVar20 = (char)uVar17;
        if (i == uVar23) break;
        i = i + 1;
        dVar25 = dVar25 * (double)_DAT_0041183c;
        pcVar20 = pcVar21;
        bVar2 = bVar1;
      }
      if (!bVar2) {
        dVar25 = local_3c;
      }
      if (local_4c + (double)DAT_00411848._4_4_ < dVar25) {
LAB_00409e46:
        do {
          pcVar20 = pcVar21 + -1;
          if ((char)uVar17 != '9') goto code_r0x00409e4e;
          if (local_60 == pcVar20) {
            local_34 = local_34 + 1;
            cVar14 = '1';
            goto LAB_00409e55;
          }
          uVar17 = (uint)(byte)pcVar21[-2];
          pcVar21 = pcVar20;
        } while( true );
      }
      if (dVar25 < (double)DAT_00411848._4_4_ - local_4c) {
        local_88 = (uint)NAN(dVar25);
        if (dVar25 != 0.0) {
          local_88 = 1;
        }
        local_88 = local_88 << 4;
LAB_0040ae60:
        do {
          pcVar20 = pcVar21;
          pcVar21 = pcVar20 + -1;
        } while (pcVar20[-1] == '0');
        local_68 = local_34 + 1;
        pcVar22 = local_60;
        goto LAB_0040a06d;
      }
      bVar1 = false;
      if (-1 < local_64) {
        iVar15 = 0;
        if (-1 < fpi->int_max) goto LAB_00409ff1;
        goto LAB_0040a440;
      }
      iVar15 = 0;
      local_98 = (__Bigint *)0x0;
      goto LAB_0040a1c6;
    }
LAB_0040a0d0:
    if (dVar25 - (double)(float)DAT_00411848 <= local_4c) {
      if (-local_4c <= dVar25 - (double)(float)DAT_00411848) goto LAB_0040a100;
      goto LAB_0040a328;
    }
    local_68 = 2;
    local_98 = (__Bigint *)0x0;
    local_84._0_4_ = (__Bigint *)0x0;
LAB_0040a045:
    *local_60 = '1';
    local_88 = 0x20;
    pcVar22 = local_60;
    local_60 = local_60 + 1;
  }
  else {
    local_a0 = 0;
    bVar1 = iVar15 + 0x3fdU < 0x7f8;
LAB_00409e98:
    i = (int)ROUND((double)iVar11 * _DAT_00411830) + 3;
    local_60 = __rv_alloc_D2A(i);
    iVar15 = fpi->rounding + -1;
    if (iVar15 != 0) {
      local_94 = (char *)0x0;
      bVar2 = true;
      local_40 = 0xffffffff;
      uVar6 = 0xffffffff;
      goto LAB_00409c7f;
    }
    local_94 = (char *)0x0;
    uVar6 = 0xffffffff;
    if (-1 < local_64) {
      bVar2 = true;
      local_40 = 0xffffffff;
      goto LAB_00409fe0;
    }
    local_40 = 0xffffffff;
LAB_0040a138:
    i = (iVar11 - iVar7) + 1;
    if (local_64 - (iVar11 - iVar7) < fpi->emin) {
      if ((local_a0 - 3 & 0xfffffffd) == 0) {
LAB_0040a853:
        if ((int)(uVar6 - 1) <= local_50) {
          iVar16 = local_50 - (uVar6 - 1);
          if ((int)uVar6 < 0) {
            i = 0;
            iVar24 = local_5c - uVar6;
          }
          else {
            local_68 = local_68 + uVar6;
            local_5c = uVar6 + local_5c;
            i = uVar6;
          }
          goto LAB_0040a1a8;
        }
      }
      else {
        i = (local_64 - fpi->emin) + 1;
        if (((int)local_a0 < 2 || (int)uVar6 < 1) || (i <= (int)uVar6)) goto LAB_0040a194;
        if ((int)(uVar6 - 1) <= local_50) {
          iVar16 = local_50 - (uVar6 - 1);
          local_68 = local_68 + uVar6;
          local_5c = uVar6 + local_5c;
          i = uVar6;
          goto LAB_0040a1a8;
        }
      }
      local_68 = local_68 + uVar6;
      local_6c = local_6c + ((uVar6 - 1) - local_50);
      iVar16 = 0;
      local_5c = uVar6 + local_5c;
      local_50 = uVar6 - 1;
      i = uVar6;
    }
    else {
      if (1 < (int)local_a0) goto LAB_0040a853;
LAB_0040a194:
      local_68 = local_68 + i;
      local_5c = i + local_5c;
    }
LAB_0040a1a8:
    local_98 = __i2b_D2A(1);
    bVar1 = true;
LAB_0040a1c6:
    if ((0 < iVar24) && (0 < (int)local_68)) {
      i = local_68;
      if (iVar24 <= (int)local_68) {
        i = iVar24;
      }
      local_5c = local_5c - i;
      local_68 = local_68 - i;
      iVar24 = iVar24 - i;
    }
    p_Var10 = b;
    if (local_50 != 0) {
      if ((bVar1) && (iVar16 != 0)) {
        local_98 = __pow5mult_D2A(local_98,iVar16);
        p_Var10 = __mult_D2A(local_98,b);
        __Bfree_D2A(b);
        local_50 = local_50 - iVar16;
        if (local_50 == 0) goto LAB_0040a216;
      }
      p_Var10 = __pow5mult_D2A(p_Var10,local_50);
    }
LAB_0040a216:
    local_84._0_4_ = __i2b_D2A(1);
    if (local_6c == 0) {
      if ((((int)local_a0 < 2) && (iVar7 == 1)) && (fpi->emin + 1 < be)) {
        local_5c = local_5c + 1;
        local_68 = local_68 + 1;
        local_6c = 1;
      }
      uVar23 = 0x1f;
    }
    else {
      local_84._0_4_ = __pow5mult_D2A((__Bigint *)local_84,local_6c);
      if ((((int)local_a0 < 2) && (iVar7 == 1)) && (fpi->emin + 1 < be)) {
        local_5c = local_5c + 1;
        local_68 = local_68 + 1;
        local_6c = 1;
      }
      else {
        local_6c = 0;
      }
      uVar23 = 0x1f;
      if (((__Bigint *)local_84)->x[((__Bigint *)local_84)->wds + -1] != 0) {
        for (; ((__Bigint *)local_84)->x[((__Bigint *)local_84)->wds + -1] >> uVar23 == 0;
            uVar23 = uVar23 - 1) {
        }
      }
      uVar23 = uVar23 ^ 0x1f;
    }
    uVar23 = (uVar23 - local_68) - 4 & 0x1f;
    b = p_Var10;
    i = uVar23;
    if (0 < (int)(local_5c + uVar23)) {
      b = __lshift_D2A(p_Var10,local_5c + uVar23);
    }
    if (0 < (int)(local_68 + i)) {
      local_84._0_4_ = __lshift_D2A((__Bigint *)local_84,local_68 + i);
    }
    bVar2 = (int)local_a0 < 3;
    if ((bVar4) && (iVar11 = __cmp_D2A(b,(__Bigint *)local_84), iVar11 < 0)) {
      b = __multadd_D2A(b,10,0);
      uVar6 = local_58 - 1;
      if (bVar1) {
        local_98 = __multadd_D2A(local_98,10,0);
        if (bVar2 || 0 < (int)local_40) {
          local_68 = local_58;
LAB_0040a467:
          p_Var10 = local_98;
          if (0 < (int)(uVar23 + iVar24)) {
            p_Var10 = __lshift_D2A(local_98,uVar23 + iVar24);
          }
          local_98 = p_Var10;
          if (local_6c != 0) {
            p_Var12 = __Balloc_D2A(p_Var10->k);
            memcpy(&p_Var12->sign,&p_Var10->sign,p_Var10->wds * 4 + 8);
            local_98 = __lshift_D2A(p_Var12,1);
          }
          local_94 = local_60;
          i = 1;
          do {
            iVar11 = __quorem_D2A(b,(__Bigint *)local_84);
            uVar23 = iVar11 + 0x30;
            iVar7 = __cmp_D2A(b,p_Var10);
            p_Var12 = __diff_D2A((__Bigint *)local_84,local_98);
            if (p_Var12->sign == 0) {
              iVar18 = __cmp_D2A(b,p_Var12);
              __Bfree_D2A(p_Var12);
              if ((iVar18 != 0 || local_a0 != 0) || (iVar18 = 0, (*bits & 1) != 0 || iVar15 != 0))
              goto LAB_0040a4ad;
              if (uVar23 != 0x39) {
                if (iVar7 < 1) {
                  local_88 = 0x10;
                  if (b->wds < 2) {
                    local_88 = (uint)(b->x[0] != 0) << 4;
                  }
                }
                else {
                  local_88 = 0x20;
                  uVar23 = iVar11 + 0x31;
                }
                *local_94 = (char)uVar23;
                pcVar20 = local_94 + 1;
                goto LAB_0040a630;
              }
LAB_0040ad97:
              pcVar20 = local_94 + 1;
              goto LAB_0040ad9e;
            }
            __Bfree_D2A(p_Var12);
            iVar18 = 1;
LAB_0040a4ad:
            if ((iVar7 < 0) || ((iVar7 == 0 && local_a0 == 0 && ((*bits & 1) == 0)))) {
              if (iVar15 == 0) {
                local_88 = 0;
                if (0 < iVar18) {
LAB_0040ad31:
                  b = __lshift_D2A(b,1);
                  iVar7 = __cmp_D2A(b,(__Bigint *)local_84);
                  if ((iVar7 < 1) && ((iVar7 != 0 || ((uVar23 & 1) == 0)))) {
                    local_88 = 0x20;
                  }
                  else {
                    if (uVar23 == 0x39) goto LAB_0040ad97;
                    local_88 = 0x20;
                    uVar23 = iVar11 + 0x31;
                  }
                }
                if ((b->wds < 2) && (b->x[0] == 0)) {
                  pcVar20 = local_94 + 1;
                  goto LAB_0040abd3;
                }
              }
              else {
                if ((b->wds < 2) && (b->x[0] == 0)) {
                  if (0 < iVar18) goto LAB_0040ad31;
                  pcVar20 = local_94 + 1;
                  goto LAB_0040abd3;
                }
                local_a0 = uVar23;
                if (iVar15 != 2) goto LAB_0040ab96;
              }
              local_88 = 0x10;
              pcVar20 = local_94 + 1;
              goto LAB_0040abd3;
            }
            pcVar20 = local_94 + 1;
            local_90 = (char)uVar23;
            if ((0 < iVar18) && (iVar15 != 2)) {
              if (uVar23 == 0x39) goto LAB_0040ad9e;
              local_88 = 0x20;
              *local_94 = local_90 + '\x01';
              goto LAB_0040a630;
            }
            *local_94 = local_90;
            if (i == local_40) goto LAB_0040a771;
            b = __multadd_D2A(b,10,0);
            if (p_Var10 == local_98) {
              p_Var10 = __multadd_D2A(p_Var10,10,0);
              local_98 = p_Var10;
            }
            else {
              p_Var10 = __multadd_D2A(p_Var10,10,0);
              local_98 = __multadd_D2A(local_98,10,0);
            }
            i = i + 1;
            local_94 = pcVar20;
          } while( true );
        }
      }
      else if (bVar2 || 0 < (int)local_40) {
        local_68 = local_58;
        goto LAB_0040a700;
      }
    }
    else {
      local_40 = uVar6;
      if ((0 < (int)uVar6) || (uVar6 = local_58, bVar2)) {
        local_68 = local_58 + 1;
        if (bVar1) goto LAB_0040a467;
LAB_0040a700:
        i = 1;
        pcVar21 = local_60;
        while( true ) {
          pcVar20 = pcVar21 + 1;
          iVar11 = __quorem_D2A(b,(__Bigint *)local_84);
          uVar23 = iVar11 + 0x30;
          *pcVar21 = (char)uVar23;
          if ((int)local_40 <= i) break;
          b = __multadd_D2A(b,10,0);
          i = i + 1;
          pcVar21 = pcVar20;
        }
        p_Var10 = (__Bigint *)0x0;
LAB_0040a771:
        if (iVar15 == 0) {
          b = __lshift_D2A(b,1);
          iVar11 = __cmp_D2A(b,(__Bigint *)local_84);
          pcVar21 = pcVar20;
          if ((0 < iVar11) || ((iVar11 == 0 && ((uVar23 & 1) != 0)))) {
LAB_0040a9a0:
            do {
              pcVar20 = pcVar21;
              pcVar21 = pcVar20 + -1;
              if (pcVar20[-1] != '9') {
                local_88 = 0x20;
                *pcVar21 = pcVar20[-1] + '\x01';
                goto LAB_0040a630;
              }
            } while (local_60 != pcVar21);
            local_68 = local_68 + 1;
            local_88 = 0x20;
            *local_60 = '1';
            goto LAB_0040a630;
          }
LAB_0040aad7:
          local_88 = 0x10;
          pcVar21 = pcVar20;
          if (b->wds < 2) {
            UVar13 = b->x[0];
            goto LAB_0040a79d;
          }
        }
        else {
          if (iVar15 == 2) goto LAB_0040aad7;
          pcVar21 = pcVar20;
          if ((1 < b->wds) || (UVar13 = 0, b->x[0] != 0)) goto LAB_0040a9a0;
LAB_0040a79d:
          local_88 = (uint)(UVar13 != 0) << 4;
          pcVar21 = pcVar20;
        }
        do {
          pcVar20 = pcVar21;
          pcVar21 = pcVar20 + -1;
        } while (pcVar20[-1] == '0');
        goto LAB_0040a630;
      }
    }
    local_58 = uVar6;
    if (local_40 == 0) {
      local_84._0_4_ = __multadd_D2A((__Bigint *)local_84,5,0);
      iVar11 = __cmp_D2A(b,(__Bigint *)local_84);
      if (0 < iVar11) {
        local_68 = local_58 + 2;
        goto LAB_0040a045;
      }
    }
LAB_0040a332:
    local_88 = 0x10;
    local_68 = -(int)local_94;
    pcVar22 = local_60;
  }
  __Bfree_D2A((__Bigint *)local_84);
  pcVar20 = local_60;
  if (local_98 == (__Bigint *)0x0) goto LAB_0040a06d;
LAB_0040a065:
  local_60 = pcVar20;
  __Bfree_D2A(local_98);
  pcVar20 = local_60;
LAB_0040a06d:
  local_60 = pcVar20;
  __Bfree_D2A(b);
  *local_60 = '\0';
  *decpt = local_68;
  if (rve != (char **)0x0) {
    *rve = local_60;
  }
  *kindp = *kindp | local_88;
  return pcVar22;
}



// --- Function: __rshift_D2A @ 0040b020 ---

/* WARNING: Unknown calling convention */

void __rshift_D2A(__Bigint *b,int k)

{
  ULong *pUVar1;
  ULong *pUVar2;
  int iVar3;
  sbyte sVar4;
  int iVar5;
  uint uVar6;
  ULong *pUVar7;
  uint *puVar8;
  uint *puVar9;
  ULong *pUVar10;
  ULong *pUVar11;
  byte local_20;
  
                    /* Unresolved local var: ULong * x@[???]
                       Unresolved local var: ULong * x1@[???]
                       Unresolved local var: ULong * xe@[???]
                       Unresolved local var: ULong y@[???]
                       Unresolved local var: int n@[???] */
  iVar3 = b->wds;
  iVar5 = k >> 5;
  if (iVar5 < iVar3) {
    pUVar1 = b->x;
    pUVar7 = pUVar1 + iVar3;
    pUVar10 = pUVar1 + iVar5;
    if ((k & 0x1fU) == 0) {
      pUVar11 = pUVar1;
      if (pUVar7 <= pUVar10) goto LAB_0040b043;
      do {
        pUVar2 = pUVar10 + 1;
        *pUVar11 = *pUVar10;
        pUVar10 = pUVar2;
        pUVar11 = pUVar11 + 1;
      } while (pUVar2 < pUVar7);
      pUVar7 = pUVar1 + (iVar3 - iVar5);
    }
    else {
      puVar8 = pUVar10 + 1;
      sVar4 = (sbyte)(k & 0x1fU);
      local_20 = 0x20 - sVar4;
      uVar6 = *pUVar10 >> sVar4;
      pUVar10 = pUVar1;
      if (puVar8 < pUVar7) {
        do {
          puVar9 = puVar8 + 1;
          *pUVar10 = uVar6 | *puVar8 << (local_20 & 0x1f);
          uVar6 = *puVar8 >> sVar4;
          puVar8 = puVar9;
          pUVar10 = pUVar10 + 1;
        } while (puVar9 < pUVar7);
        pUVar7 = (ULong *)((int)b + (iVar3 - iVar5) * 4 + 0x10);
        *pUVar7 = uVar6;
        if (uVar6 == 0) goto LAB_0040b10a;
      }
      else {
        b->x[0] = uVar6;
        pUVar7 = pUVar1;
        if (uVar6 == 0) goto LAB_0040b043;
      }
      pUVar7 = pUVar7 + 1;
    }
LAB_0040b10a:
    b->wds = (int)pUVar7 - (int)pUVar1 >> 2;
    if (pUVar7 != pUVar1) {
      return;
    }
  }
  else {
LAB_0040b043:
    b->wds = 0;
  }
  b->x[0] = 0;
  return;
}



// --- Function: __trailz_D2A @ 0040b150 ---

/* WARNING: Unknown calling convention */

int __trailz_D2A(__Bigint *b)

{
  ULong *pUVar1;
  uint uVar2;
  int iVar3;
  ULong *pUVar4;
  int iVar5;
  
                    /* Unresolved local var: ULong L@[???]
                       Unresolved local var: ULong * x@[???]
                       Unresolved local var: ULong * xe@[???]
                       Unresolved local var: int n@[???] */
  pUVar4 = b->x;
  pUVar1 = pUVar4 + b->wds;
  iVar5 = 0;
  while( true ) {
    if (pUVar1 <= pUVar4) {
      return iVar5;
    }
    if (*pUVar4 != 0) break;
    pUVar4 = pUVar4 + 1;
    iVar5 = iVar5 + 0x20;
  }
  if (pUVar1 <= pUVar4) {
    return iVar5;
  }
                    /* Unresolved local var: int ret@[???] */
  iVar3 = 0;
  for (uVar2 = *pUVar4; (uVar2 & 1) == 0; uVar2 = uVar2 >> 1 | 0x80000000) {
    iVar3 = iVar3 + 1;
  }
  return iVar5 + iVar3;
}



// --- Function: dtoa_lock @ 0040b190 ---

/* WARNING: Removing unreachable block (ram,0x0040b253) */
/* WARNING: Removing unreachable block (ram,0x0040b240) */
/* WARNING: Removing unreachable block (ram,0x0040b245) */

void __cdecl dtoa_lock(int n)

{
  int in_EAX;
  
  if (dtoa_CS_init != 2) {
    if (dtoa_CS_init != 0) {
      if (dtoa_CS_init == 1) {
        do {
          Sleep(1);
        } while (dtoa_CS_init == 1);
        if (dtoa_CS_init == 2) goto LAB_0040b21b;
      }
      return;
    }
                    /* Unresolved local var: long last_CS_init@[???] */
    LOCK();
    dtoa_CS_init = 1;
    UNLOCK();
                    /* Unresolved local var: int i@[???] */
    InitializeCriticalSection((LPCRITICAL_SECTION)dtoa_CritSec);
    InitializeCriticalSection((LPCRITICAL_SECTION)(dtoa_CritSec + 1));
    atexit(dtoa_lock_cleanup);
    dtoa_CS_init = 2;
  }
LAB_0040b21b:
  EnterCriticalSection((LPCRITICAL_SECTION)(dtoa_CritSec + in_EAX));
  return;
}



// --- Function: dtoa_lock_cleanup @ 0040b260 ---

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void dtoa_lock_cleanup(void)

{
  long lVar1;
  
                    /* Unresolved local var: long last_CS_init@[???] */
  lVar1 = dtoa_CS_init;
  LOCK();
  dtoa_CS_init = 3;
  UNLOCK();
  if (lVar1 != 2) {
    return;
  }
                    /* Unresolved local var: long last_CS_init@[???]
                       Unresolved local var: int i@[???] */
  DeleteCriticalSection((LPCRITICAL_SECTION)dtoa_CritSec);
  DeleteCriticalSection((LPCRITICAL_SECTION)(dtoa_CritSec + 1));
  return;
}



// --- Function: __Balloc_D2A @ 0040b2a0 ---

/* WARNING: Unknown calling convention */

__Bigint * __Balloc_D2A(int k)

{
  uint uVar1;
  int iVar2;
  __Bigint *p_Var3;
  int iVar4;
  int in_stack_ffffffd4;
  
                    /* Unresolved local var: int x@[???]
                       Unresolved local var: __Bigint * rv@[???]
                       Unresolved local var: uint len@[???] */
  dtoa_lock(in_stack_ffffffd4);
  iVar2 = dtoa_CS_init;
  if (k < 10) {
    p_Var3 = freelist[k];
    if (p_Var3 != (__Bigint *)0x0) {
      freelist[k] = p_Var3->next;
      goto joined_r0x0040b31c;
    }
    iVar4 = 1 << ((byte)k & 0x1f);
    uVar1 = iVar4 * 4 + 0x1b;
    if (0x120 < ((int)(pmem_next + -0x82a1c) >> 3) + (uVar1 >> 3)) goto LAB_0040b2f0;
    p_Var3 = (__Bigint *)pmem_next;
    pmem_next = (double *)((uVar1 & 0xfffffff8) + (int)pmem_next);
  }
  else {
LAB_0040b2f0:
    iVar4 = 1 << ((byte)k & 0x1f);
    p_Var3 = (__Bigint *)malloc(iVar4 * 4 + 0x1bU & 0xfffffff8);
    if (p_Var3 == (__Bigint *)0x0) {
      return (__Bigint *)0x0;
    }
  }
  iVar2 = dtoa_CS_init;
  p_Var3->k = k;
  p_Var3->maxwds = iVar4;
joined_r0x0040b31c:
  if (iVar2 == 2) {
    LeaveCriticalSection((LPCRITICAL_SECTION)dtoa_CritSec);
  }
  p_Var3->wds = 0;
  p_Var3->sign = 0;
  return p_Var3;
}



// --- Function: __Bfree_D2A @ 0040b380 ---

/* WARNING: Unknown calling convention */

void __Bfree_D2A(__Bigint *v)

{
  __Bigint *p_Var1;
  bool bVar2;
  int in_stack_ffffffe4;
  
  if (v != (__Bigint *)0x0) {
    if (9 < v->k) {
      free(v);
      return;
    }
    dtoa_lock(in_stack_ffffffe4);
    bVar2 = dtoa_CS_init == 2;
    p_Var1 = freelist[v->k];
    freelist[v->k] = v;
    v->next = p_Var1;
    if (bVar2) {
      LeaveCriticalSection((LPCRITICAL_SECTION)dtoa_CritSec);
    }
  }
  return;
}



// --- Function: __multadd_D2A @ 0040b3f0 ---

/* WARNING: Unknown calling convention */

__Bigint * __multadd_D2A(__Bigint *b,int m,int a)

{
  int iVar1;
  longlong lVar2;
  uint uVar3;
  ULong UVar4;
  __Bigint *p_Var5;
  int iVar6;
  int iVar7;
  
                    /* Unresolved local var: int i@[???]
                       Unresolved local var: int wds@[???]
                       Unresolved local var: ULong * x@[???]
                       Unresolved local var: ulonglong carry@[???]
                       Unresolved local var: ulonglong y@[???]
                       Unresolved local var: __Bigint * b1@[???] */
  iVar6 = 0;
  iVar1 = b->wds;
  iVar7 = a >> 0x1f;
  do {
    lVar2 = (ulonglong)(uint)m * (ulonglong)b->x[iVar6];
    uVar3 = (uint)lVar2;
    UVar4 = uVar3 + a;
    a = (int)((ulonglong)lVar2 >> 0x20) + (m >> 0x1f) * b->x[iVar6] + iVar7 + (uint)CARRY4(uVar3,a);
    b->x[iVar6] = UVar4;
    iVar7 = 0;
    iVar6 = iVar6 + 1;
  } while (iVar6 < iVar1);
  p_Var5 = b;
  if (a != 0) {
    if (iVar1 < b->maxwds) {
      b->x[iVar1] = a;
      b->wds = iVar1 + 1;
    }
    else {
      p_Var5 = __Balloc_D2A(b->k + 1);
      if (p_Var5 != (__Bigint *)0x0) {
        memcpy(&p_Var5->sign,&b->sign,b->wds * 4 + 8);
        __Bfree_D2A(b);
        p_Var5->x[iVar1] = a;
        p_Var5->wds = iVar1 + 1;
      }
    }
  }
  return p_Var5;
}



// --- Function: __i2b_D2A @ 0040b4d0 ---

/* WARNING: Unknown calling convention */

__Bigint * __i2b_D2A(int i)

{
  int iVar1;
  __Bigint *p_Var2;
  int in_stack_ffffffd4;
  
                    /* Unresolved local var: __Bigint * b@[???]
                       Unresolved local var: int x@[???]
                       Unresolved local var: __Bigint * rv@[???]
                       Unresolved local var: uint len@[???] */
  dtoa_lock(in_stack_ffffffd4);
  if (freelist[1] == (__Bigint *)0x0) {
    if (((int)(pmem_next + -0x82a1c) >> 3) + 4U < 0x121) {
      p_Var2 = (__Bigint *)pmem_next;
      pmem_next = pmem_next + 4;
    }
    else {
      p_Var2 = (__Bigint *)malloc(0x20);
      if (p_Var2 == (__Bigint *)0x0) {
        return (__Bigint *)0x0;
      }
    }
    iVar1 = dtoa_CS_init;
    p_Var2->k = 1;
    p_Var2->maxwds = 2;
  }
  else {
    p_Var2 = freelist[1];
    freelist[1] = freelist[1]->next;
    iVar1 = dtoa_CS_init;
  }
  if (iVar1 == 2) {
    LeaveCriticalSection((LPCRITICAL_SECTION)dtoa_CritSec);
  }
  p_Var2->sign = 0;
  p_Var2->wds = 1;
  p_Var2->x[0] = i;
  return p_Var2;
}



// --- Function: __mult_D2A @ 0040b580 ---

/* WARNING: Unknown calling convention */

__Bigint * __mult_D2A(__Bigint *a,__Bigint *b)

{
  ULong *pUVar1;
  ULong *pUVar2;
  uint uVar3;
  longlong lVar4;
  int k;
  __Bigint *p_Var5;
  ULong *pUVar6;
  int iVar7;
  ULong *pUVar8;
  int iVar10;
  int iVar11;
  ULong *pUVar12;
  ULong *pUVar13;
  uint local_4c;
  ULong *pUVar9;
  
                    /* Unresolved local var: __Bigint * c@[???]
                       Unresolved local var: int k@[???]
                       Unresolved local var: int wa@[???]
                       Unresolved local var: int wb@[???]
                       Unresolved local var: int wc@[???]
                       Unresolved local var: ULong * x@[???]
                       Unresolved local var: ULong * xa@[???]
                       Unresolved local var: ULong * xae@[???]
                       Unresolved local var: ULong * xb@[???]
                       Unresolved local var: ULong * xbe@[???]
                       Unresolved local var: ULong * xc@[???]
                       Unresolved local var: ULong * xc0@[???]
                       Unresolved local var: ULong y@[???]
                       Unresolved local var: ulonglong carry@[???]
                       Unresolved local var: ulonglong z@[???] */
  p_Var5 = a;
  iVar11 = b->wds;
  iVar10 = a->wds;
  iVar7 = iVar10;
  if (iVar11 <= iVar10) {
    a = b;
    iVar7 = iVar11;
    iVar11 = iVar10;
    b = p_Var5;
  }
  k = b->k;
  iVar10 = iVar11 + iVar7;
  if (b->maxwds < iVar10) {
    k = k + 1;
  }
  p_Var5 = __Balloc_D2A(k);
  if (p_Var5 != (__Bigint *)0x0) {
    pUVar13 = p_Var5->x;
    if (pUVar13 < pUVar13 + iVar10) {
      memset(pUVar13,0,((uint)((int)(pUVar13 + iVar10) + (-0x15 - (int)p_Var5)) & 0xfffffffc) + 4);
    }
    pUVar1 = b->x + iVar11;
    pUVar12 = a->x;
    pUVar2 = pUVar12 + iVar7;
    if (pUVar12 < pUVar2) {
      iVar11 = 4;
      if ((uint *)((int)b->x + 1) <= pUVar1) {
        iVar11 = ((int)pUVar1 + (-0x15 - (int)b) & 0xfffffffcU) + 4;
      }
      do {
        while( true ) {
          uVar3 = *pUVar12;
          pUVar12 = pUVar12 + 1;
          if (uVar3 == 0) break;
          local_4c = 0;
          pUVar6 = pUVar13;
          pUVar8 = b->x;
          do {
            pUVar9 = pUVar8 + 1;
            lVar4 = (ulonglong)uVar3 * (ulonglong)*pUVar8 + (ulonglong)*pUVar6 + (ulonglong)local_4c
            ;
            local_4c = (uint)((ulonglong)lVar4 >> 0x20);
            *pUVar6 = (uint)lVar4;
            pUVar6 = pUVar6 + 1;
            pUVar8 = pUVar9;
          } while (pUVar9 < pUVar1);
          *(uint *)((int)pUVar13 + iVar11) = local_4c;
          pUVar13 = pUVar13 + 1;
          if (pUVar2 <= pUVar12) goto LAB_0040b6f9;
        }
        pUVar13 = pUVar13 + 1;
      } while (pUVar12 < pUVar2);
    }
LAB_0040b6f9:
    if (0 < iVar10) {
      do {
        if (p_Var5->x[iVar10 + -1] != 0) break;
        iVar10 = iVar10 + -1;
      } while (iVar10 != 0);
    }
    p_Var5->wds = iVar10;
  }
  return p_Var5;
}



// --- Function: __pow5mult_D2A @ 0040b720 ---

/* WARNING: Unknown calling convention */

__Bigint * __pow5mult_D2A(__Bigint *b,int k)

{
  PRTL_CRITICAL_SECTION_DEBUG b_00;
  uint uVar1;
  PRTL_CRITICAL_SECTION_DEBUG a;
  PRTL_CRITICAL_SECTION_DEBUG a_00;
  PRTL_CRITICAL_SECTION_DEBUG in_stack_ffffffd4;
  
                    /* Unresolved local var: __Bigint * b1@[???]
                       Unresolved local var: __Bigint * p5@[???]
                       Unresolved local var: __Bigint * p51@[???]
                       Unresolved local var: int i@[???] */
  if (((k & 3U) == 0) ||
     (in_stack_ffffffd4 = (PRTL_CRITICAL_SECTION_DEBUG)b,
     b = __multadd_D2A(b,*(int *)(&DAT_0041185c + (k & 3U) * 4),0),
     (PRTL_CRITICAL_SECTION_DEBUG)b != (PRTL_CRITICAL_SECTION_DEBUG)0x0)) {
    uVar1 = k >> 2;
    if (uVar1 != 0) {
      b_00 = (PRTL_CRITICAL_SECTION_DEBUG)p5s;
      if (p5s == (__Bigint *)0x0) {
        dtoa_lock((int)in_stack_ffffffd4);
        b_00 = (PRTL_CRITICAL_SECTION_DEBUG)p5s;
        if (p5s == (__Bigint *)0x0) {
                    /* Unresolved local var: __Bigint * b@[???] */
          in_stack_ffffffd4 = (PRTL_CRITICAL_SECTION_DEBUG)0x1;
          b_00 = (PRTL_CRITICAL_SECTION_DEBUG)__Balloc_D2A(1);
          if (b_00 == (PRTL_CRITICAL_SECTION_DEBUG)0x0) {
            p5s = (__Bigint *)0x0;
            return (__Bigint *)0x0;
          }
          b_00->ContentionCount = 0x271;
          b_00->EntryCount = 1;
          p5s = (__Bigint *)b_00;
          b_00->Type = 0;
          b_00->CreatorBackTraceIndex = 0;
        }
        if (dtoa_CS_init == 2) {
          in_stack_ffffffd4 = (PRTL_CRITICAL_SECTION_DEBUG)(dtoa_CritSec + 1);
          LeaveCriticalSection((LPCRITICAL_SECTION)(dtoa_CritSec + 1));
        }
      }
      a = (PRTL_CRITICAL_SECTION_DEBUG)b;
      if ((uVar1 & 1) != 0) goto LAB_0040b771;
      while (uVar1 = (int)uVar1 >> 1, a_00 = b_00, uVar1 != 0) {
        while( true ) {
          b_00 = *(PRTL_CRITICAL_SECTION_DEBUG *)&a_00->Type;
          if (b_00 == (PRTL_CRITICAL_SECTION_DEBUG)0x0) {
            dtoa_lock((int)in_stack_ffffffd4);
            b_00 = *(PRTL_CRITICAL_SECTION_DEBUG *)&a_00->Type;
            if (b_00 == (PRTL_CRITICAL_SECTION_DEBUG)0x0) {
              in_stack_ffffffd4 = a_00;
              b_00 = (PRTL_CRITICAL_SECTION_DEBUG)__mult_D2A((__Bigint *)a_00,(__Bigint *)a_00);
              *(PRTL_CRITICAL_SECTION_DEBUG *)&a_00->Type = b_00;
              if (b_00 == (PRTL_CRITICAL_SECTION_DEBUG)0x0) goto LAB_0040b815;
              b_00->Type = 0;
              b_00->CreatorBackTraceIndex = 0;
            }
            if (dtoa_CS_init == 2) {
              in_stack_ffffffd4 = (PRTL_CRITICAL_SECTION_DEBUG)(dtoa_CritSec + 1);
              LeaveCriticalSection((LPCRITICAL_SECTION)(dtoa_CritSec + 1));
            }
          }
          a = (PRTL_CRITICAL_SECTION_DEBUG)b;
          if ((uVar1 & 1) == 0) break;
LAB_0040b771:
          b = __mult_D2A((__Bigint *)a,(__Bigint *)b_00);
          if ((PRTL_CRITICAL_SECTION_DEBUG)b == (PRTL_CRITICAL_SECTION_DEBUG)0x0) goto LAB_0040b815;
          __Bfree_D2A((__Bigint *)a);
          uVar1 = (int)uVar1 >> 1;
          a_00 = b_00;
          in_stack_ffffffd4 = a;
          if (uVar1 == 0) {
            return (__Bigint *)(PRTL_CRITICAL_SECTION_DEBUG)b;
          }
        }
      }
    }
  }
  else {
LAB_0040b815:
    b = (__Bigint *)0x0;
  }
  return (__Bigint *)(PRTL_CRITICAL_SECTION_DEBUG)b;
}



// --- Function: __lshift_D2A @ 0040b8a0 ---

/* WARNING: Unknown calling convention */

__Bigint * __lshift_D2A(__Bigint *b,int k)

{
  ULong *pUVar1;
  uint *puVar2;
  uint *puVar3;
  int iVar4;
  sbyte sVar5;
  int iVar6;
  __Bigint *p_Var7;
  uint uVar8;
  int iVar9;
  ULong *pUVar10;
  int iVar11;
  int iVar12;
  ULong *pUVar13;
  ULong *pUVar14;
  ULong *pUVar15;
  
                    /* Unresolved local var: int i@[???]
                       Unresolved local var: int k1@[???]
                       Unresolved local var: int n@[???]
                       Unresolved local var: int n1@[???]
                       Unresolved local var: __Bigint * b1@[???]
                       Unresolved local var: ULong * x@[???]
                       Unresolved local var: ULong * x1@[???]
                       Unresolved local var: ULong * xe@[???]
                       Unresolved local var: ULong z@[???] */
  iVar9 = b->k;
  iVar12 = k >> 5;
  iVar6 = b->wds + iVar12;
  iVar11 = iVar6 + 1;
  for (iVar4 = b->maxwds; iVar4 < iVar11; iVar4 = iVar4 * 2) {
    iVar9 = iVar9 + 1;
  }
  p_Var7 = __Balloc_D2A(iVar9);
  if (p_Var7 == (__Bigint *)0x0) {
    return (__Bigint *)0x0;
  }
  pUVar14 = p_Var7->x;
  pUVar15 = pUVar14;
  if (0 < iVar12) {
    pUVar15 = pUVar14 + iVar12;
    memset(pUVar14,0,iVar12 * 4);
  }
  pUVar14 = b->x;
  pUVar1 = pUVar14 + b->wds;
  if ((k & 0x1fU) == 0) {
    do {
      puVar3 = pUVar15 + 1;
      puVar2 = pUVar14 + 1;
      *pUVar15 = *pUVar14;
      if (pUVar1 <= puVar2) break;
      pUVar15 = pUVar15 + 2;
      pUVar14 = pUVar14 + 2;
      *puVar3 = *puVar2;
    } while (pUVar14 < pUVar1);
  }
  else {
    sVar5 = (sbyte)(k & 0x1fU);
    uVar8 = 0;
    pUVar10 = pUVar15;
    do {
      pUVar13 = pUVar14 + 1;
      *pUVar10 = uVar8 | *pUVar14 << sVar5;
      uVar8 = *pUVar14 >> (0x20U - sVar5 & 0x1f);
      pUVar10 = pUVar10 + 1;
      pUVar14 = pUVar13;
    } while (pUVar13 < pUVar1);
    iVar9 = ((int)pUVar1 + (-0x15 - (int)b) & 0xfffffffcU) + 4;
    if (pUVar1 < (uint *)((int)b->x + 1U)) {
      iVar9 = 4;
    }
    *(uint *)((int)pUVar15 + iVar9) = uVar8;
    if (uVar8 != 0) goto LAB_0040b9a6;
  }
  iVar11 = iVar6;
LAB_0040b9a6:
  p_Var7->wds = iVar11;
  __Bfree_D2A(b);
  return p_Var7;
}



// --- Function: __cmp_D2A @ 0040b9e0 ---

/* WARNING: Unknown calling convention */

int __cmp_D2A(__Bigint *a,__Bigint *b)

{
  int iVar1;
  ULong *pUVar2;
  ULong *pUVar3;
  int iVar4;
  
                    /* Unresolved local var: ULong * xa@[???]
                       Unresolved local var: ULong * xa0@[???]
                       Unresolved local var: ULong * xb@[???]
                       Unresolved local var: ULong * xb0@[???]
                       Unresolved local var: int i@[???]
                       Unresolved local var: int j@[???] */
  iVar1 = b->wds;
  iVar4 = a->wds - iVar1;
  if (iVar4 == 0) {
    pUVar2 = a->x + iVar1;
    pUVar3 = b->x + iVar1;
    do {
      pUVar2 = pUVar2 + -1;
      pUVar3 = pUVar3 + -1;
      if (*pUVar2 != *pUVar3) {
        return -(uint)(*pUVar2 < *pUVar3) | 1;
      }
    } while (a->x < pUVar2);
  }
  return iVar4;
}



// --- Function: __diff_D2A @ 0040ba30 ---

/* WARNING: Unknown calling convention */

__Bigint * __diff_D2A(__Bigint *a,__Bigint *b)

{
  ULong *pUVar1;
  int iVar2;
  ULong *pUVar3;
  uint uVar4;
  ULong UVar5;
  int iVar6;
  int iVar7;
  uint *puVar8;
  uint *puVar9;
  ULong *pUVar10;
  ULong *pUVar11;
  __Bigint *p_Var12;
  uint *puVar13;
  ULong *pUVar14;
  ULong *pUVar15;
  uint uVar16;
  ULong *local_4c;
  ULong *local_40;
  __Bigint *local_38;
  
                    /* Unresolved local var: __Bigint * c@[???]
                       Unresolved local var: int i@[???]
                       Unresolved local var: int wa@[???]
                       Unresolved local var: int wb@[???]
                       Unresolved local var: ULong * xa@[???]
                       Unresolved local var: ULong * xae@[???]
                       Unresolved local var: ULong * xb@[???]
                       Unresolved local var: ULong * xbe@[???]
                       Unresolved local var: ULong * xc@[???]
                       Unresolved local var: ulonglong borrow@[???]
                       Unresolved local var: ulonglong y@[???] */
                    /* Unresolved local var: ULong * xa@[???]
                       Unresolved local var: ULong * xa0@[???]
                       Unresolved local var: ULong * xb@[???]
                       Unresolved local var: ULong * xb0@[???]
                       Unresolved local var: int i@[???]
                       Unresolved local var: int j@[???] */
  iVar6 = b->wds;
  p_Var12 = b;
  if (a->wds == iVar6) {
    pUVar3 = a->x + iVar6;
    pUVar10 = b->x + iVar6;
    do {
      pUVar3 = pUVar3 + -1;
      pUVar10 = pUVar10 + -1;
      if (*pUVar3 != *pUVar10) {
        if (*pUVar3 < *pUVar10) goto LAB_0040bc0b;
        iVar7 = 0;
        goto LAB_0040ba80;
      }
    } while (a->x < pUVar3);
    local_38 = __Balloc_D2A(0);
    if (local_38 != (__Bigint *)0x0) {
      local_38->wds = 1;
      local_38->x[0] = 0;
      return local_38;
    }
  }
  else {
    iVar7 = 0;
    if (a->wds - iVar6 < 0) {
LAB_0040bc0b:
      iVar7 = 1;
      p_Var12 = a;
      a = b;
    }
LAB_0040ba80:
    local_38 = __Balloc_D2A(a->k);
    if (local_38 != (__Bigint *)0x0) {
      local_38->sign = iVar7;
      iVar6 = a->wds;
      pUVar3 = a->x;
      pUVar10 = local_38->x;
      pUVar11 = pUVar3 + iVar6;
      pUVar1 = p_Var12->x + p_Var12->wds;
      uVar16 = 0;
      pUVar14 = p_Var12->x;
      local_4c = pUVar3;
      local_40 = pUVar10;
      do {
        pUVar15 = pUVar14 + 1;
        uVar4 = *local_4c - *pUVar14;
        UVar5 = uVar4 - uVar16;
        uVar16 = -(uint)(uVar4 < uVar16) - (uint)(*local_4c < *pUVar14) & 1;
        *local_40 = UVar5;
        pUVar14 = pUVar15;
        local_4c = local_4c + 1;
        local_40 = local_40 + 1;
      } while (pUVar15 < pUVar1);
      puVar9 = (uint *)((int)p_Var12->x + 1);
      uVar4 = (uint)((int)pUVar1 + (-0x15 - (int)p_Var12)) >> 2;
      iVar7 = uVar4 * 4 + 4;
      if (pUVar1 < puVar9) {
        iVar7 = 4;
      }
      puVar13 = (uint *)((int)pUVar3 + iVar7);
      puVar8 = puVar13;
      pUVar3 = (ULong *)((int)pUVar10 + iVar7);
      if (puVar13 < pUVar11) {
        do {
          puVar9 = puVar8 + 1;
          UVar5 = *puVar8 - uVar16;
          uVar16 = -(uint)(*puVar8 < uVar16) & 1;
          *pUVar3 = UVar5;
          puVar8 = puVar9;
          pUVar3 = pUVar3 + 1;
        } while (puVar9 < pUVar11);
        iVar7 = (int)pUVar10 + iVar7 + ((int)pUVar11 + (-1 - (int)puVar13) & 0xfffffffcU);
      }
      else {
        iVar7 = uVar4 << 2;
        if (pUVar1 < puVar9) {
          iVar7 = 0;
        }
        iVar7 = (int)pUVar10 + iVar7;
      }
      if (UVar5 == 0) {
        iVar2 = iVar6 * -4;
        do {
          iVar6 = iVar6 + -1;
        } while (*(int *)(iVar7 + iVar2 + iVar6 * 4) == 0);
      }
      local_38->wds = iVar6;
    }
  }
  return local_38;
}



// --- Function: __b2d_D2A @ 0040bc80 ---

/* WARNING: Unknown calling convention */

double __b2d_D2A(__Bigint *a,int *e)

{
  ULong *pUVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  byte bVar5;
  uint uVar6;
  
                    /* Unresolved local var: ULong * xa@[???]
                       Unresolved local var: ULong * xa0@[???]
                       Unresolved local var: ULong w@[???]
                       Unresolved local var: ULong y@[???]
                       Unresolved local var: ULong z@[???]
                       Unresolved local var: int k@[???]
                       Unresolved local var: _dbl_union d@[???] */
  pUVar1 = a->x;
  iVar2 = a->wds;
  uVar6 = pUVar1[iVar2 + -1];
  uVar3 = 0x1f;
  if (uVar6 != 0) {
    for (; uVar6 >> uVar3 == 0; uVar3 = uVar3 - 1) {
    }
  }
  uVar3 = uVar3 ^ 0x1f;
  *e = 0x20 - uVar3;
  if (10 < (int)uVar3) {
    bVar5 = (byte)(uVar3 - 0xb);
    if (pUVar1 < pUVar1 + iVar2 + -1) {
      uVar4 = pUVar1[iVar2 + -2];
      if (uVar3 - 0xb != 0) {
        uVar6 = uVar6 << (bVar5 & 0x1f) | uVar4 >> (0x20 - bVar5 & 0x1f);
        uVar4 = uVar4 << (bVar5 & 0x1f);
        if (pUVar1 < pUVar1 + iVar2 + -2) {
          return (double)(CONCAT44(uVar6,uVar4 | pUVar1[iVar2 + -3] >> (0x20 - bVar5 & 0x1f)) |
                         0x3ff0000000000000);
        }
      }
    }
    else {
      if (uVar3 != 0xb) {
        return (double)((ulonglong)(uVar6 << (bVar5 & 0x1f)) << 0x20 | 0x3ff0000000000000);
      }
      uVar4 = 0;
    }
    return (double)(CONCAT44(uVar6,uVar4) | 0x3ff0000000000000);
  }
  bVar5 = 0xb - (char)uVar3;
  uVar4 = 0;
  if (pUVar1 < pUVar1 + iVar2 + -1) {
    uVar4 = pUVar1[iVar2 + -2] >> (bVar5 & 0x1f);
  }
  return (double)(CONCAT44(uVar6 >> (bVar5 & 0x1f),uVar6 << ((char)uVar3 + 0x15U & 0x1f) | uVar4) |
                 0x3ff0000000000000);
}



// --- Function: __d2b_D2A @ 0040bdc0 ---

/* WARNING: Unknown calling convention */

__Bigint * __d2b_D2A(double dd,int *e,int *bits)

{
  int iVar1;
  __Bigint *p_Var2;
  uint uVar3;
  __Bigint *p_Var4;
  uint uVar5;
  byte bVar6;
  int iVar7;
  __Bigint *p_Var8;
  ULong UVar9;
  uint local_24;
  uint uStack_20;
  
                    /* Unresolved local var: __Bigint * b@[???]
                       Unresolved local var: _dbl_union d@[???]
                       Unresolved local var: int i@[???]
                       Unresolved local var: int de@[???]
                       Unresolved local var: int k@[???]
                       Unresolved local var: ULong * x@[???]
                       Unresolved local var: ULong y@[???]
                       Unresolved local var: ULong z@[???] */
  p_Var4 = __Balloc_D2A(1);
  if (p_Var4 != (__Bigint *)0x0) {
    uStack_20 = (uint)((ulonglong)dd >> 0x20);
    local_24 = SUB84(dd,0);
    uVar5 = uStack_20 >> 0x14 & 0x7ff;
    p_Var8 = (__Bigint *)(uStack_20 & 0xfffff);
    if (uVar5 != 0) {
      p_Var8 = (__Bigint *)(uStack_20 & 0xfffff | 0x100000);
    }
    if (local_24 == 0) {
                    /* Unresolved local var: int ret@[???] */
      iVar7 = 0;
      for (p_Var2 = p_Var8; ((uint)p_Var2 & 1) == 0;
          p_Var2 = (__Bigint *)((uint)p_Var2 >> 1 | 0x80000000)) {
        iVar7 = iVar7 + 1;
      }
      iVar1 = iVar7 + 0x20;
      p_Var4->x[0] = (uint)p_Var8 >> ((byte)iVar7 & 0x1f);
      iVar7 = 1;
      p_Var4->wds = 1;
    }
    else {
                    /* Unresolved local var: int ret@[???] */
      iVar1 = 0;
      for (uVar3 = local_24; (uVar3 & 1) == 0; uVar3 = uVar3 >> 1 | 0x80000000) {
        iVar1 = iVar1 + 1;
      }
      bVar6 = (byte)iVar1;
      UVar9 = local_24 >> (bVar6 & 0x1f);
      if (iVar1 != 0) {
        UVar9 = UVar9 | (int)p_Var8 << (0x20 - bVar6 & 0x1f);
        p_Var8 = (__Bigint *)((uint)p_Var8 >> (bVar6 & 0x1f));
      }
      p_Var4[1].next = p_Var8;
      iVar7 = 2 - (uint)(p_Var8 == (__Bigint *)0x0);
      p_Var4->x[0] = UVar9;
      p_Var4->wds = iVar7;
    }
    if (uVar5 == 0) {
      *e = iVar1 + -0x432;
      uVar5 = 0x1f;
      if (p_Var4->x[iVar7 + -1] != 0) {
        for (; p_Var4->x[iVar7 + -1] >> uVar5 == 0; uVar5 = uVar5 - 1) {
        }
      }
      iVar7 = iVar7 * 0x20 - (uVar5 ^ 0x1f);
    }
    else {
      iVar7 = 0x35 - iVar1;
      *e = (uVar5 - 0x433) + iVar1;
    }
    *bits = iVar7;
    return p_Var4;
  }
  return (__Bigint *)0x0;
}



// --- Function: __strcp_D2A @ 0040beb0 ---

/* WARNING: Unknown calling convention */

char * __strcp_D2A(char *a,char *b)

{
  char cVar1;
  
  cVar1 = *b;
  *a = cVar1;
  while (cVar1 != '\0') {
    b = b + 1;
    cVar1 = *b;
    a = a + 1;
    *a = cVar1;
  }
  return a;
}



// --- Function: __increment_D2A @ 0040bee0 ---

/* WARNING: Unknown calling convention */

__Bigint * __increment_D2A(__Bigint *b)

{
  ULong *pUVar1;
  ULong *pUVar2;
  __Bigint *p_Var3;
  int iVar4;
  
                    /* Unresolved local var: ULong * x@[???]
                       Unresolved local var: ULong * xe@[???]
                       Unresolved local var: __Bigint * b1@[???] */
  iVar4 = b->wds;
  pUVar2 = b->x;
  do {
    if (*pUVar2 != 0xffffffff) {
      *pUVar2 = *pUVar2 + 1;
      return b;
    }
    pUVar1 = pUVar2 + 1;
    *pUVar2 = 0;
    pUVar2 = pUVar1;
  } while (pUVar1 < b->x + iVar4);
  p_Var3 = b;
  if (b->maxwds <= iVar4) {
    p_Var3 = __Balloc_D2A(b->k + 1);
    memcpy(&p_Var3->sign,&b->sign,b->wds * 4 + 8);
    __Bfree_D2A(b);
    iVar4 = p_Var3->wds;
  }
  p_Var3->wds = iVar4 + 1;
  p_Var3->x[iVar4] = 1;
  return p_Var3;
}



// --- Function: rvOK @ 0040bf80 ---

int __fastcall rvOK(dbl_union *d,FPI *fpi,long *expo,ULong *bits,int exact,int rd,int *irv)

{
  int k;
  uint n;
  uint uVar1;
  uint *in_EAX;
  __Bigint *b;
  uint uVar2;
  int *piVar3;
  int k_00;
  int k_01;
  int iVar4;
  ULong local_38;
  uint local_34;
  int bdif;
  int e;
  
                    /* Unresolved local var: __Bigint * b@[???]
                       Unresolved local var: ULong carry@[???]
                       Unresolved local var: ULong inex@[???]
                       Unresolved local var: ULong lostbits@[???]
                       Unresolved local var: int j@[???]
                       Unresolved local var: int k@[???]
                       Unresolved local var: int k1@[???]
                       Unresolved local var: int nb@[???]
                       Unresolved local var: int rv@[???] */
  b = __d2b_D2A((double)CONCAT44(bits,expo),&e,&bdif);
  n = *in_EAX;
  k_01 = bdif - n;
  e = e + k_01;
  if (k_01 < 1) {
    iVar4 = 0;
    if (exact == 0) goto LAB_0040c08c;
    if (k_01 != 0) {
      iVar4 = n - bdif;
      bdif = k_01;
      b = __lshift_D2A(b,iVar4);
      k_01 = bdif;
    }
    bdif = k_01;
    local_38 = 0;
    local_34 = 0;
  }
  else {
    if (n == 0x35) {
      iVar4 = 0;
      if ((exact == 0) || (in_EAX[3] != 1)) goto LAB_0040c08c;
LAB_0040c1d0:
      bdif = k_01;
      local_38 = __any_on_D2A(b,k_01);
      __rshift_D2A(b,bdif);
    }
    else {
      if (rd == 1) goto LAB_0040c1d0;
      if (rd == 2) {
        bdif = k_01;
        local_38 = __any_on_D2A(b,k_01);
        __rshift_D2A(b,bdif);
LAB_0040c00e:
        b = __increment_D2A(b);
        uVar2 = 0;
        if ((n & 0x1f) != 0) {
          uVar2 = 0x20 - (n & 0x1f);
        }
        uVar1 = 0x1f;
        if (b->x[b->wds + -1] != 0) {
          for (; b->x[b->wds + -1] >> uVar1 == 0; uVar1 = uVar1 - 1) {
          }
        }
        if ((uVar1 ^ 0x1f) == uVar2) {
          local_34 = 0x20;
        }
        else {
          if (local_38 == 0) {
            local_38 = b->x[0] & 1;
          }
          __rshift_D2A(b,1);
          local_34 = 0x20;
          e = e + 1;
        }
        goto LAB_0040c0c1;
      }
      iVar4 = k_01 + -1;
      if (iVar4 == 0) {
        iVar4 = 0;
        if (exact == 0) goto LAB_0040c08c;
        uVar2 = b->x[0] >> 1;
      }
      else {
        uVar2 = b->x[iVar4 >> 5] >> ((byte)iVar4 & 0x1f);
      }
      bdif = k_01;
      local_38 = __any_on_D2A(b,k_01);
      __rshift_D2A(b,bdif);
      if ((uVar2 & 1) != 0) goto LAB_0040c00e;
    }
    local_34 = (uint)(local_38 != 0) << 4;
  }
LAB_0040c0c1:
  uVar2 = in_EAX[1];
  if (e < (int)uVar2) {
    k_00 = uVar2 - e;
    e = uVar2;
    if (((int)n < k_00) || (in_EAX[4] != 0)) {
      b->wds = 0;
      *irv = 0x50;
      uVar2 = 0;
    }
    else {
      k = k_00 + -1;
      if ((0 < k) && (local_38 == 0)) {
        local_38 = __any_on_D2A(b,k);
      }
      iVar4 = 0;
      k_01 = bdif;
      if (local_38 == 0 && exact == 0) goto LAB_0040c08c;
      uVar2 = b->x[k >> 5];
      __rshift_D2A(b,k_00);
      *irv = 2;
      if ((1 << ((byte)k & 0x1f) & uVar2) == 0) {
        uVar2 = 0x50;
        if (local_38 == 0) {
          uVar2 = local_34;
        }
      }
      else {
        b = __increment_D2A(b);
        uVar2 = 0x60;
      }
    }
  }
  else {
    uVar2 = local_34;
    if ((int)in_EAX[2] < e) {
      e = in_EAX[2] + 1;
      *irv = 0xa3;
      piVar3 = __errno();
      *piVar3 = 0x22;
      b->wds = 0;
      uVar2 = 0;
    }
  }
  iVar4 = 1;
  fpi->nbits = e;
  __copybits_D2A(d->L,n,b);
  *irv = *irv | uVar2;
  k_01 = bdif;
LAB_0040c08c:
  bdif = k_01;
  __Bfree_D2A(b);
  return iVar4;
}



// --- Function: __decrement_D2A @ 0040c300 ---

/* WARNING: Unknown calling convention */

void __decrement_D2A(__Bigint *b)

{
  int iVar1;
  ULong *pUVar2;
  ULong *pUVar3;
  
                    /* Unresolved local var: ULong * x@[???]
                       Unresolved local var: ULong * xe@[???] */
  iVar1 = b->wds;
  pUVar3 = b->x;
  do {
    if (*pUVar3 != 0) {
      *pUVar3 = *pUVar3 - 1;
      return;
    }
    pUVar2 = pUVar3 + 1;
    *pUVar3 = 0xffffffff;
    pUVar3 = pUVar2;
  } while (pUVar2 < b->x + iVar1);
  return;
}



// --- Function: __set_ones_D2A @ 0040c340 ---

/* WARNING: Unknown calling convention */

__Bigint * __set_ones_D2A(__Bigint *b,int n)

{
  ULong *pUVar1;
  ULong *pUVar2;
  size_t sVar3;
  int iVar4;
  ULong *pUVar5;
  
                    /* Unresolved local var: int k@[???]
                       Unresolved local var: ULong * x@[???]
                       Unresolved local var: ULong * xe@[???] */
  iVar4 = n + 0x1f >> 5;
  if (b->k < iVar4) {
    __Bfree_D2A(b);
    b = __Balloc_D2A(iVar4);
  }
  pUVar1 = b->x;
  iVar4 = n >> 5;
  if ((n & 0x1fU) == 0) {
    b->wds = iVar4;
    pUVar2 = pUVar1 + iVar4;
    if (pUVar1 < pUVar2) {
      sVar3 = ((uint)((int)pUVar2 + (-0x15 - (int)b)) & 0xfffffffc) + 4;
      if (pUVar2 < (undefined1 *)((int)b->x + 1U)) {
        sVar3 = 4;
      }
      memset(pUVar1,0xff,sVar3);
    }
    return b;
  }
  b->wds = iVar4 + 1;
  pUVar2 = pUVar1 + iVar4 + 1;
  pUVar5 = pUVar1;
  if (pUVar1 < pUVar2) {
    sVar3 = ((uint)((int)pUVar2 + (-0x15 - (int)b)) & 0xfffffffc) + 4;
    if (pUVar2 < (undefined1 *)((int)b->x + 1U)) {
      sVar3 = 4;
    }
    pUVar5 = (ULong *)((int)pUVar1 + sVar3);
    memset(pUVar1,0xff,sVar3);
  }
  pUVar5[-1] = pUVar5[-1] >> (0x20U - (char)(n & 0x1fU) & 0x1f);
  return b;
}



// --- Function: __strtodg @ 0040c430 ---

/* WARNING: Type propagation algorithm not settling */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* WARNING: Unknown calling convention */

int __strtodg(char *s00,char **se,FPI *fpi,long *expo,ULong *bits)

{
  int n;
  bool bVar1;
  double dd;
  bool bVar2;
  bool bVar3;
  __Bigint *v;
  char *pcVar4;
  undefined4 *puVar5;
  int iVar6;
  uint uVar7;
  char *pcVar8;
  int *piVar9;
  int iVar10;
  int iVar11;
  __Bigint *p_Var12;
  int iVar13;
  __Bigint *b;
  __Bigint *b_00;
  ULong *pUVar14;
  char cVar15;
  char *pcVar16;
  int iVar17;
  __Bigint *p_Var18;
  int iVar19;
  int iVar20;
  uint uVar21;
  int iVar22;
  uint uVar23;
  char *pcVar24;
  int iVar25;
  undefined8 local_ac;
  __Bigint *local_a0;
  __Bigint *local_9c;
  uint local_98;
  uint local_94;
  double local_8c;
  uint local_80;
  double local_7c;
  int local_74;
  int local_68;
  uint local_64;
  uint local_4c;
  int local_48;
  int local_44;
  int abe;
  int abits;
  int irv;
  int rvbits;
  int rve;
  char *s;
  __Bigint *rvb;
  
                    /* Unresolved local var: int asub@[???]
                       Unresolved local var: int bb0@[???]
                       Unresolved local var: int bb2@[???]
                       Unresolved local var: int bb5@[???]
                       Unresolved local var: int bbe@[???]
                       Unresolved local var: int bd2@[???]
                       Unresolved local var: int bd5@[???]
                       Unresolved local var: int bbbits@[???]
                       Unresolved local var: int bs2@[???]
                       Unresolved local var: int c@[???]
                       Unresolved local var: int decpt@[???]
                       Unresolved local var: int denorm@[???]
                       Unresolved local var: int dsign@[???]
                       Unresolved local var: int e@[???]
                       Unresolved local var: int e1@[???]
                       Unresolved local var: int e2@[???]
                       Unresolved local var: int emin@[???]
                       Unresolved local var: int esign@[???]
                       Unresolved local var: int finished@[???]
                       Unresolved local var: int i@[???]
                       Unresolved local var: int inex@[???]
                       Unresolved local var: int j@[???]
                       Unresolved local var: int k@[???]
                       Unresolved local var: int nbits@[???]
                       Unresolved local var: int nd@[???]
                       Unresolved local var: int nd0@[???]
                       Unresolved local var: int nf@[???]
                       Unresolved local var: int nz@[???]
                       Unresolved local var: int nz0@[???]
                       Unresolved local var: int rd@[???]
                       Unresolved local var: int rve1@[???]
                       Unresolved local var: int sign@[???]
                       Unresolved local var: int sudden_underflow@[???]
                       Unresolved local var: char * s0@[???]
                       Unresolved local var: char * s1@[???]
                       Unresolved local var: double adj0@[???]
                       Unresolved local var: double tol@[???]
                       Unresolved local var: long L@[???]
                       Unresolved local var: _dbl_union adj@[???]
                       Unresolved local var: _dbl_union rv@[???]
                       Unresolved local var: ULong * b@[???]
                       Unresolved local var: ULong * be@[???]
                       Unresolved local var: ULong y@[???]
                       Unresolved local var: ULong z@[???]
                       Unresolved local var: __Bigint * ab@[???]
                       Unresolved local var: __Bigint * bb@[???]
                       Unresolved local var: __Bigint * bb1@[???]
                       Unresolved local var: __Bigint * bd@[???]
                       Unresolved local var: __Bigint * bd0@[???]
                       Unresolved local var: __Bigint * bs@[???]
                       Unresolved local var: __Bigint * delta@[???]
                       Unresolved local var: __Bigint * rvb0@[???]
                       Unresolved local var: char * decimalpoint@[???]
                       Unresolved local var: int dplen@[???] */
  puVar5 = (undefined4 *)localeconv();
  pcVar16 = (char *)*puVar5;
  iVar6 = strlen(pcVar16);
  irv = 0;
  rvb = (__Bigint *)0x0;
  n = fpi->nbits;
  pcVar8 = s00;
LAB_0040c477:
  cVar15 = *pcVar8;
  switch(cVar15) {
  case '\0':
switchD_0040c48b_caseD_0:
    if (se != (char **)0x0) {
      *se = s00;
    }
    return 6;
  default:
    local_68 = 0;
    s = pcVar8;
    goto LAB_0040c4a0;
  case '\t':
  case '\n':
  case '\v':
  case '\f':
  case '\r':
  case ' ':
    goto switchD_0040c48b_caseD_9;
  case '+':
    local_68 = 0;
    break;
  case '-':
    local_68 = 1;
  }
  s = pcVar8 + 1;
  cVar15 = pcVar8[1];
  if (cVar15 != '\0') {
LAB_0040c4a0:
    bVar2 = false;
    if (cVar15 != '0') goto LAB_0040c4b1;
    if ((s[1] & 0xdfU) != 0x58) goto LAB_0040c7d8;
    irv = __gethex_D2A(&s,fpi,expo,&rvb,local_68);
    if (irv != 6) goto LAB_0040c630;
    s = s00;
    if (se != (char **)0x0) {
      *se = s00;
    }
    goto LAB_0040c65b;
  }
  goto switchD_0040c48b_caseD_0;
switchD_0040c48b_caseD_9:
  pcVar8 = pcVar8 + 1;
  goto LAB_0040c477;
LAB_0040c7d8:
  do {
    s = s + 1;
    cVar15 = *s;
  } while (cVar15 == '0');
  if (cVar15 == '\0') goto LAB_0040c630;
  bVar2 = true;
LAB_0040c4b1:
  pcVar8 = s;
  local_48 = fpi->sudden_underflow;
  uVar7 = (uint)cVar15;
  if (uVar7 - 0x30 < 10) {
    p_Var18 = (__Bigint *)0x0;
    local_a0 = (__Bigint *)0x0;
    local_8c._0_4_ = 0;
    do {
      if ((int)p_Var18 < 9) {
        local_8c._0_4_ = (uVar7 - 0x30) + local_8c._0_4_ * 10;
      }
      else if ((int)p_Var18 < 0x10) {
        local_a0 = (__Bigint *)((uVar7 - 0x30) + (int)local_a0 * 10);
      }
      p_Var18 = (__Bigint *)((int)p_Var18 + 1);
      cVar15 = s[(int)p_Var18];
      uVar7 = (uint)cVar15;
      pcVar24 = s + (int)p_Var18;
    } while (uVar7 - 0x30 < 10);
  }
  else {
    local_a0 = (__Bigint *)0x0;
    p_Var18 = (__Bigint *)0x0;
    local_8c._0_4_ = 0;
    pcVar24 = s;
  }
  s = pcVar24;
  local_9c = p_Var18;
  if (*pcVar16 == cVar15) {
    cVar15 = pcVar16[1];
    if (cVar15 == '\0') {
      iVar10 = 1;
    }
    else {
      iVar10 = 1;
      do {
        if (s[iVar10] != cVar15) goto LAB_0040c580;
        iVar10 = iVar10 + 1;
        cVar15 = pcVar16[iVar10];
      } while (cVar15 != '\0');
    }
    s = s + iVar10;
    uVar7 = (uint)*s;
    if (p_Var18 == (__Bigint *)0x0) {
      pcVar16 = s;
      if (uVar7 == 0x30) {
        do {
          pcVar24 = pcVar16;
          pcVar16 = pcVar24 + 1;
          uVar7 = (uint)*pcVar16;
        } while (uVar7 == 0x30);
        pcVar24 = pcVar24 + (1 - (int)s);
        s = pcVar16;
      }
      else {
        pcVar24 = (char *)0x0;
      }
      pcVar16 = s;
      if (uVar7 - 0x31 < 9) {
        uVar21 = uVar7 - 0x30;
        local_9c = (__Bigint *)0x1;
        local_7c._0_4_ = pcVar24 + 1;
        goto LAB_0040d204;
      }
      local_7c._0_4_ = (char *)0x0;
      local_9c = (__Bigint *)0x0;
    }
    else {
      pcVar24 = (char *)0x0;
      local_7c._0_4_ = (char *)0x0;
      pcVar16 = s;
      s = pcVar8;
      while (uVar21 = uVar7 - 0x30, pcVar8 = s, uVar21 < 10) {
        pcVar24 = pcVar24 + 1;
        if (uVar21 != 0) {
          if (pcVar24 == (char *)0x1) {
            uVar7 = (int)local_9c + 1;
          }
          else {
            uVar7 = (int)local_9c + (int)pcVar24;
            uVar23 = (uint)local_9c;
            do {
              local_9c = (__Bigint *)(uVar23 + 1);
              if (uVar23 < 9) {
                local_8c._0_4_ = local_8c._0_4_ * 10;
              }
              else if ((int)local_9c < 0x11) {
                local_a0 = (__Bigint *)((int)local_a0 * 10);
              }
              uVar23 = (uint)local_9c;
            } while ((__Bigint *)(uVar7 + -1) != local_9c);
          }
          local_7c._0_4_ = local_7c._0_4_ + (int)pcVar24;
          bVar1 = (int)local_9c < 9;
          local_9c = (__Bigint *)uVar7;
          if (bVar1) {
LAB_0040d204:
            local_8c._0_4_ = uVar21 + local_8c._0_4_ * 10;
            pcVar24 = (char *)0x0;
          }
          else {
            pcVar24 = (char *)0x0;
            if ((int)uVar7 < 0x11) {
              local_a0 = (__Bigint *)(uVar21 + (int)local_a0 * 10);
            }
          }
        }
        uVar7 = (uint)pcVar16[1];
        pcVar16 = pcVar16 + 1;
      }
    }
    s = pcVar16;
    bVar1 = true;
  }
  else {
LAB_0040c580:
    pcVar24 = (char *)0x0;
    local_7c._0_4_ = (char *)0x0;
    bVar1 = false;
  }
  pcVar16 = s;
  if ((uVar7 & 0xffffffdf) == 0x45) {
    if ((local_9c != (__Bigint *)0x0 || pcVar24 != (char *)0x0) || bVar2) {
      s00 = s;
      cVar15 = s[1];
      if (cVar15 == '+') {
        bVar3 = false;
LAB_0040d0d0:
        cVar15 = s[2];
        s = s + 2;
      }
      else {
        if (cVar15 == '-') {
          bVar3 = true;
          goto LAB_0040d0d0;
        }
        bVar3 = false;
        s = s + 1;
      }
      uVar7 = (uint)cVar15;
      uVar21 = uVar7 - 0x30;
      if (9 < uVar21) {
        local_80 = 0;
        uVar21 = local_80;
        s = pcVar16;
        goto LAB_0040c5ac;
      }
      if (uVar7 == 0x30) {
        do {
          s = s + 1;
          uVar7 = (uint)*s;
        } while (uVar7 == 0x30);
        local_80 = 0;
        uVar21 = local_80;
        if (8 < uVar7 - 0x31) goto LAB_0040c5ac;
        uVar21 = uVar7 - 0x30;
      }
      uVar7 = (uint)s[1];
      pcVar16 = s + 1;
      if (uVar7 - 0x30 < 10) {
        pcVar4 = s + 2;
        do {
          pcVar16 = pcVar4;
          uVar21 = (uVar7 - 0x30) + uVar21 * 10;
          uVar7 = (uint)*pcVar16;
          pcVar4 = pcVar16 + 1;
        } while (uVar7 - 0x30 < 10);
        local_80 = 19999;
        iVar10 = (int)pcVar16 - (int)s;
        s = pcVar16;
        if (iVar10 < 9) goto LAB_0040dc34;
      }
      else {
LAB_0040dc34:
        s = pcVar16;
        local_80 = 19999;
        if ((int)uVar21 < 20000) {
          local_80 = uVar21;
        }
      }
      uVar21 = -local_80;
      if (!bVar3) {
        uVar21 = local_80;
      }
      goto LAB_0040c5ac;
    }
    goto LAB_0040c610;
  }
  local_80 = 0;
  uVar21 = local_80;
  s = pcVar16;
LAB_0040c5ac:
  local_80 = uVar21;
  if (local_9c == (__Bigint *)0x0) {
    if (bVar2 || pcVar24 != (char *)0x0) goto LAB_0040c630;
    if (bVar1) goto LAB_0040c610;
    if (uVar7 == 0x69) {
LAB_0040d272:
      iVar6 = __match_D2A(&s,"nf");
      if (iVar6 != 0) {
        s = s + -1;
        iVar6 = __match_D2A(&s,"inity");
        if (iVar6 == 0) {
          s = s + 1;
        }
        irv = 3;
LAB_0040d2c0:
        *expo = fpi->emax + 1;
        goto LAB_0040c630;
      }
    }
    else if ((int)uVar7 < 0x6a) {
      if (uVar7 == 0x49) goto LAB_0040d272;
      if (uVar7 == 0x4e) goto LAB_0040c5e9;
    }
    else if (uVar7 == 0x6e) {
LAB_0040c5e9:
      iVar6 = __match_D2A(&s,"an");
      if (iVar6 != 0) {
        irv = 4;
        *expo = fpi->emax + 1;
        if (*s != '(') goto LAB_0040c630;
        irv = __hexnan_D2A(&s,fpi,bits);
        goto LAB_0040d2c0;
      }
    }
LAB_0040c610:
    irv = 6;
    s = s00;
    goto LAB_0040c630;
  }
  irv = 1;
  iVar10 = local_80 - (int)local_7c._0_4_;
  uVar7 = fpi->rounding & 3;
  local_64 = uVar7 - local_68;
  if ((uVar7 != 2) && (local_64 = local_68 + 1, uVar7 != 3)) {
    local_64 = (uint)(uVar7 == 0);
  }
  if (p_Var18 == (__Bigint *)0x0) {
    p_Var18 = local_9c;
  }
  p_Var12 = (__Bigint *)0x10;
  if ((int)local_9c < 0x11) {
    p_Var12 = local_9c;
  }
  local_ac = (double)local_8c._0_4_;
  if (9 < (int)local_9c) {
    local_ac = (double)ZEXT48(local_a0);
    local_ac = (double)(longlong)local_ac +
               *(double *)(&DAT_00411838 + (int)p_Var12 * 8) * (double)local_8c._0_4_;
  }
  if ((n < 0x36) && ((int)local_9c < 0x10)) {
    if (iVar10 == 0) {
      uVar7 = 1;
LAB_0040c9ea:
      iVar11 = rvOK((dbl_union *)bits,(FPI *)expo,SUB84(local_ac,0),
                    (ULong *)((ulonglong)local_ac >> 0x20),uVar7,local_64,&irv);
      if (iVar11 != 0) goto LAB_0040c630;
      uVar21 = (int)local_9c - (int)p_Var12;
      uVar7 = uVar21;
      if (0 < (int)uVar21) goto LAB_0040ca1c;
LAB_0040d030:
      iVar11 = 0;
      dd = local_ac;
      if (uVar7 == 0) goto LAB_0040ca38;
    }
    else {
      if (0 < iVar10) {
        if (0x16 < iVar10) {
          if (0x25 - (int)local_9c < iVar10) {
            uVar7 = (int)local_9c + (iVar10 - (int)p_Var12);
            goto LAB_0040d018;
          }
          local_ac = local_ac * __tens_D2A[0xf - (int)local_9c] *
                     __tens_D2A[iVar10 - (0xf - (int)local_9c)];
          goto LAB_0040deae;
        }
                    /* Unresolved local var: ULong L@[???] */
        if ((uint)local_ac == 0) {
          iVar11 = 0;
                    /* Unresolved local var: int ret@[???] */
          for (uVar7 = local_ac._4_4_ | 0x100000; (uVar7 & 1) == 0; uVar7 = uVar7 >> 1 | 0x80000000)
          {
            iVar11 = iVar11 + 1;
          }
          local_a0 = (__Bigint *)(0x15 - iVar11);
        }
        else {
                    /* Unresolved local var: int ret@[???] */
          iVar11 = 0;
          for (uVar7 = (uint)local_ac; (uVar7 & 1) == 0; uVar7 = uVar7 >> 1 | 0x80000000) {
            iVar11 = iVar11 + 1;
          }
          local_a0 = (__Bigint *)(0x35 - iVar11);
        }
        local_ac = local_ac * __tens_D2A[iVar10];
        uVar7 = (uint)(fivesbits[iVar10] + (int)local_a0 < 0x36);
        goto LAB_0040c9ea;
      }
      uVar7 = (int)local_9c + (iVar10 - (int)p_Var12);
      if (-0x17 < iVar10) {
        local_ac = local_ac / __tens_D2A[(int)local_7c._0_4_ - local_80];
LAB_0040deae:
        uVar7 = 0;
        goto LAB_0040c9ea;
      }
    }
    uVar7 = -uVar7;
    if ((uVar7 & 0xf) != 0) {
      local_ac = local_ac / __tens_D2A[uVar7 & 0xf];
    }
    iVar11 = 0;
    dd = local_ac;
    if ((uVar7 & 0xfffffff0) != 0) {
      uVar21 = (int)uVar7 >> 4;
      if ((int)(uVar7 & 0xfffffff0) < 0x100) {
        iVar11 = 0;
      }
      else {
        iVar11 = 0;
        uVar7 = uVar21;
        do {
          uVar7 = uVar7 - 0x10;
          uVar23 = local_ac._4_4_ >> 0x14;
          local_ac = (double)((ulonglong)local_ac & 0x800fffffffffffff | 0x3ff0000000000000);
          iVar11 = iVar11 + -0x3ff + (uVar23 & 0x7ff);
          local_ac = local_ac * __tinytens_D2A[4];
        } while (0xf < (int)uVar7);
        uVar21 = uVar21 & 0xf;
      }
      uVar7 = local_ac._4_4_ >> 0x14;
      local_ac = (double)((ulonglong)local_ac & 0x800fffffffffffff | 0x3ff0000000000000);
      iVar11 = iVar11 + -0x3ff + (uVar7 & 0x7ff);
      dd = local_ac;
      if (uVar21 != 0) {
        bVar2 = false;
        iVar25 = 0;
        do {
          if ((uVar21 & 1) != 0) {
            dd = dd * __tinytens_D2A[iVar25];
            bVar2 = true;
          }
          iVar25 = iVar25 + 1;
          uVar21 = (int)uVar21 >> 1;
        } while (uVar21 != 0);
        if (!bVar2) {
          dd = local_ac;
        }
      }
    }
  }
  else {
    uVar7 = (int)local_9c + (iVar10 - (int)p_Var12);
    if ((int)uVar7 < 1) goto LAB_0040d030;
LAB_0040d018:
    uVar21 = uVar7 & 0xf;
    if (uVar21 != 0) {
LAB_0040ca1c:
      local_ac = local_ac * __tens_D2A[uVar21];
    }
    iVar11 = 0;
    dd = local_ac;
    if ((uVar7 & 0xfffffff0) != 0) {
      uVar21 = (int)uVar7 >> 4;
      if ((int)(uVar7 & 0xfffffff0) < 0x100) {
        iVar11 = 0;
      }
      else {
        iVar11 = 0;
        uVar7 = uVar21;
        do {
          uVar7 = uVar7 - 0x10;
          uVar23 = local_ac._4_4_ >> 0x14;
          local_ac = (double)((ulonglong)local_ac & 0x800fffffffffffff | 0x3ff0000000000000);
          iVar11 = iVar11 + -0x3ff + (uVar23 & 0x7ff);
          local_ac = local_ac * __bigtens_D2A[4];
        } while (0xf < (int)uVar7);
        uVar21 = uVar21 & 0xf;
      }
      uVar7 = local_ac._4_4_ >> 0x14;
      local_ac = (double)((ulonglong)local_ac & 0x800fffffffffffff | 0x3ff0000000000000);
      iVar11 = iVar11 + -0x3ff + (uVar7 & 0x7ff);
      dd = local_ac;
      if (uVar21 != 0) {
        bVar2 = false;
        iVar25 = 0;
        do {
          if ((uVar21 & 1) != 0) {
            dd = dd * __bigtens_D2A[iVar25];
            bVar2 = true;
          }
          iVar25 = iVar25 + 1;
          uVar21 = (int)uVar21 >> 1;
        } while (uVar21 != 0);
        if (!bVar2) {
          dd = local_ac;
        }
      }
    }
  }
LAB_0040ca38:
  rvb = __d2b_D2A(dd,&rve,&rvbits);
  rve = iVar11 + rve;
  iVar11 = rvbits - n;
  if (0 < iVar11) {
    __rshift_D2A(rvb,iVar11);
    rve = iVar11 + rve;
    rvbits = n;
  }
  local_44 = (rve + rvbits) - n;
  if (fpi->emax + 1 < local_44) {
    local_94 = 0;
    goto LAB_0040da38;
  }
  iVar11 = fpi->emin;
  if (iVar11 <= local_44) {
    local_94 = 0;
    goto LAB_0040cb6b;
  }
  iVar25 = rve - iVar11;
  if (0 < iVar25) {
    rvb = __lshift_D2A(rvb,iVar25);
    rvbits = rvbits + iVar25;
LAB_0040cb30:
    if (local_48 == 0) {
      local_94 = 1;
      local_44 = iVar11;
      rve = iVar11;
LAB_0040cb6b:
      p_Var18 = __s2b_D2A(pcVar8,(int)p_Var18,(int)local_9c,local_8c._0_4_,iVar6);
      local_98 = 0;
      iVar6 = 0;
      if (iVar10 < 0) {
        iVar6 = (int)local_7c._0_4_ - local_80;
      }
      iVar25 = 0;
      if (iVar10 >= 0) {
        iVar25 = iVar10;
      }
      do {
        local_9c = __Balloc_D2A(p_Var18->k);
        memcpy(&local_9c->sign,&p_Var18->sign,p_Var18->wds * 4 + 8);
        p_Var12 = __Balloc_D2A(rvb->k);
        memcpy(&p_Var12->sign,&rvb->sign,rvb->wds * 4 + 8);
        iVar22 = rve;
        iVar17 = rvbits;
        iVar13 = rvbits - local_98;
        iVar19 = local_98 + rve;
        local_a0 = __i2b_D2A(1);
        if (iVar19 < 0) {
          iVar20 = iVar25 - iVar19;
          iVar19 = iVar6;
        }
        else {
          iVar20 = iVar25;
          iVar19 = iVar19 + iVar6;
        }
        iVar22 = (iVar17 + iVar22) - n;
        iVar17 = (n + 1) - iVar13;
        if (iVar22 < iVar11) {
          iVar17 = (iVar22 - iVar11) + iVar17;
        }
        iVar22 = iVar19 + iVar17;
        iVar20 = iVar20 + iVar17;
        iVar17 = iVar20;
        if (iVar22 <= iVar20) {
          iVar17 = iVar22;
        }
        if (iVar19 < iVar17) {
          iVar17 = iVar19;
        }
        if (0 < iVar17) {
          iVar22 = iVar22 - iVar17;
          iVar20 = iVar20 - iVar17;
          iVar19 = iVar19 - iVar17;
        }
        b = p_Var12;
        if (0 < iVar6) {
          local_a0 = __pow5mult_D2A(local_a0,iVar6);
          b = __mult_D2A(local_a0,p_Var12);
          __Bfree_D2A(p_Var12);
        }
        iVar17 = iVar22 - local_98;
        if (iVar17 < 1) {
          if (iVar17 != 0) {
            __rshift_D2A(b,local_98 - iVar22);
          }
        }
        else {
          b = __lshift_D2A(b,iVar17);
        }
        if (0 < iVar10) {
          local_9c = __pow5mult_D2A(local_9c,iVar25);
        }
        if (0 < iVar20) {
          local_9c = __lshift_D2A(local_9c,iVar20);
        }
        if (0 < iVar19) {
          local_a0 = __lshift_D2A(local_a0,iVar19);
        }
        p_Var12 = __diff_D2A(b,local_9c);
        iVar17 = local_48;
        if ((p_Var12->wds < 2) && (p_Var12->x[0] == 0)) goto LAB_0040d6d0;
        uVar7 = p_Var12->sign;
        p_Var12->sign = 0;
        iVar22 = __cmp_D2A(p_Var12,local_a0);
        if ((local_64 == 0) || (0 < iVar22)) {
          if (iVar22 < 0) {
            if (uVar7 == 0) {
              irv = 0x21;
              if (((1 < iVar13) || (local_44 == iVar11)) || (local_94 != 0)) goto LAB_0040d6d0;
              p_Var12 = __lshift_D2A(p_Var12,1);
              iVar6 = __cmp_D2A(p_Var12,local_a0);
              uVar21 = rvbits;
              if (iVar6 < 1) goto LAB_0040d977;
              irv = 0x11;
              local_94 = 0;
LAB_0040dd04:
              rve = rve - n;
LAB_0040da11:
              rvbits = n;
              rvb = __set_ones_D2A(rvb,n);
            }
            else {
LAB_0040df37:
              irv = 0x11;
            }
          }
          else {
            if (iVar22 != 0) {
              local_7c = __ratio_D2A(p_Var12,local_a0);
              if (local_7c <= (double)_DAT_00411b00) {
                if (uVar7 == 0) {
                  local_98 = 0;
                  goto LAB_0040ce0f;
                }
                local_74 = 0;
                uVar7 = 0;
                local_8c = 1.0;
                local_4c = 0x20;
                local_7c = 1.0;
                local_98 = 0;
                goto LAB_0040ce43;
              }
              local_4c = (-(uint)(uVar7 == 0) & 0x10) + 0x10;
              local_7c = local_7c * (double)_DAT_00411b04;
              uVar7 = (uint)(uVar7 == 0);
              if (_DAT_00411b08 <= local_7c) {
                local_74 = 0;
                local_8c = local_7c;
              }
              else {
                local_74 = (int)ROUND(local_7c);
                local_8c = (double)local_74;
                local_7c = local_7c - (double)local_74;
                if (local_64 == 1) {
                  if (uVar7 != 0) {
joined_r0x0040dad6:
                    if (0.0 < local_7c) goto LAB_0040dadc;
                  }
                }
                else if (local_64 == 2) {
                  if (uVar7 == 0) goto joined_r0x0040dad6;
                }
                else if ((double)_DAT_00411b04 <= local_7c) {
LAB_0040dadc:
                  local_74 = local_74 + 1;
                  local_4c = 0x30 - local_4c;
                  local_8c = (double)local_74;
                }
              }
              local_98 = 0;
              goto LAB_0040ce43;
            }
            if (uVar7 == 0) {
              irv = 0x21;
              if (iVar13 == 1) {
                irv = 1;
                if (local_44 != iVar11) goto LAB_0040dd04;
                irv = 0x21;
                if ((rvb->wds == 1) && (iVar17 = 1, rvb->x[0] != 1)) {
                  iVar17 = local_48;
                }
                goto LAB_0040d6d0;
              }
            }
            else {
              if (local_94 != 0) {
                    /* Unresolved local var: ULong * x@[???]
                       Unresolved local var: ULong * xe@[???] */
                pUVar14 = rvb->x;
                goto LAB_0040dd54;
              }
              irv = 0x11;
            }
            if ((iVar13 < n) && (uVar21 = rvbits, local_94 == 0)) goto LAB_0040d977;
            if ((rvb->x[0] & 1) == 0) goto LAB_0040d6d0;
            if (uVar7 != 0) goto LAB_0040e042;
            if (iVar13 != 1) {
              __decrement_D2A(rvb);
              goto LAB_0040df37;
            }
LAB_0040de74:
            rvb->wds = 0;
            irv = 0x50;
            rve = iVar11;
          }
          goto LAB_0040d6d0;
        }
        uVar21 = local_64 & 1;
        local_98 = uVar21 ^ uVar7;
        if (uVar21 == uVar7) {
          irv = (-(uint)(uVar21 == 0) & 0x10) + 0x11;
          goto LAB_0040d6d0;
        }
        if (uVar7 == 0) {
          irv = 0x11;
          if (local_44 != iVar11) {
            iVar22 = 0;
            iVar19 = n;
            if (n < 0x20) {
              iVar22 = 0;
            }
            else {
              do {
                if (rvb->x[iVar22] != 0) goto LAB_0040ce0f;
                iVar19 = iVar19 + -0x20;
                iVar22 = iVar22 + 1;
              } while (0x1f < iVar19);
            }
            if (1 < iVar19) {
                    /* Unresolved local var: int ret@[???] */
              iVar20 = 0;
              uVar7 = rvb->x[iVar22];
              for (uVar21 = uVar7; (uVar21 & 1) == 0; uVar21 = uVar21 >> 1 | 0x80000000) {
                iVar20 = iVar20 + 1;
              }
              rvb->x[iVar22] = uVar7 >> ((byte)iVar20 & 0x1f);
              if (iVar20 < iVar19 + -1) goto LAB_0040ce0f;
            }
            rve = local_44 + -1;
            goto LAB_0040da11;
          }
LAB_0040ce0f:
          if ((iVar13 < 2) && (local_94 != 0)) {
            local_94 = 1;
            goto LAB_0040de74;
          }
          local_74 = 0;
          uVar7 = 1;
          local_8c = 1.0;
          local_4c = 0x10;
          local_7c = 1.0;
        }
        else {
          uVar7 = 0;
          irv = 0x21;
          local_8c = 1.0;
          local_74 = 0;
          local_7c = 1.0;
          local_4c = 0x20;
        }
LAB_0040ce43:
        iVar22 = rve + rvbits;
        if ((local_94 == 0) && (rvbits < n)) {
          iVar13 = n - rvbits;
          rvb = __lshift_D2A(rvb,iVar13);
          rve = rve - iVar13;
          rvbits = n;
        }
        b_00 = __d2b_D2A(local_8c,&abe,&abits);
        if (abe < 0) {
          __rshift_D2A(b_00,-abe);
        }
        else if (abe != 0) {
          b_00 = __lshift_D2A(b_00,abe);
        }
        v = rvb;
        if (uVar7 == 0) {
          rvb = __sum_D2A(rvb,b_00);
          iVar13 = rvb->wds;
          if (iVar13 + -1 < v->wds) {
            uVar7 = 0x1f;
            if (rvb->x[iVar13 + -1] != 0) {
              for (; rvb->x[iVar13 + -1] >> uVar7 == 0; uVar7 = uVar7 - 1) {
              }
            }
            uVar21 = 0x1f;
            if (v->x[iVar13 + -1] != 0) {
              for (; v->x[iVar13 + -1] >> uVar21 == 0; uVar21 = uVar21 - 1) {
              }
            }
            if ((int)(uVar21 ^ 0x1f) <= (int)(uVar7 ^ 0x1f)) goto LAB_0040cf10;
          }
          if (local_94 != 0) {
            rvbits = rvbits + 1;
            local_94 = (uint)(rvbits != n);
            goto LAB_0040cf10;
          }
          __rshift_D2A(rvb,1);
          rve = rve + 1;
          local_44 = local_44 + 1;
          __Bfree_D2A(b_00);
          __Bfree_D2A(v);
          uVar21 = rvbits;
          if (local_98 != 0) goto LAB_0040d977;
LAB_0040d597:
          local_98 = __trailz_D2A(rvb);
          local_94 = 0;
        }
        else {
          rvb = __diff_D2A(rvb,b_00);
          iVar13 = v->wds;
          if (local_94 == 0) {
            if (iVar13 + -1 < rvb->wds) {
              uVar21 = 0x1f;
              if (rvb->x[iVar13 + -1] != 0) {
                for (; rvb->x[iVar13 + -1] >> uVar21 == 0; uVar21 = uVar21 - 1) {
                }
              }
              uVar23 = 0x1f;
              if (v->x[iVar13 + -1] != 0) {
                for (; v->x[iVar13 + -1] >> uVar23 == 0; uVar23 = uVar23 - 1) {
                }
              }
              if ((int)(uVar21 ^ 0x1f) <= (int)(uVar23 ^ 0x1f)) goto LAB_0040cf10;
            }
            if (local_44 != iVar11) {
              rvb = __lshift_D2A(rvb,1);
              rve = rve + -1;
              local_44 = local_44 + -1;
              __Bfree_D2A(b_00);
              __Bfree_D2A(v);
              goto LAB_0040d597;
            }
            rvbits = rvbits + -1;
            local_94 = uVar7;
          }
LAB_0040cf10:
          __Bfree_D2A(b_00);
          __Bfree_D2A(v);
          if (local_98 != 0) goto LAB_0040d6d0;
          if ((rvbits + rve == iVar22) && (local_74 != 0)) {
            local_8c = local_8c * _DAT_00411b10;
            if (-local_8c <= local_7c - (double)_DAT_00411b04) {
              if ((local_8c < local_7c - (double)_DAT_00411b04) &&
                 (local_7c < (double)_DAT_00411afc - local_8c)) goto LAB_0040d6b8;
            }
            else if (local_8c < local_7c) goto LAB_0040d6b8;
          }
          if (local_94 == 0) goto LAB_0040d597;
        }
        __Bfree_D2A(b);
        __Bfree_D2A(local_9c);
        __Bfree_D2A(local_a0);
        __Bfree_D2A(p_Var12);
      } while( true );
    }
    local_94 = 1;
    iVar25 = local_44 + 1;
    local_44 = iVar11;
    rve = iVar11;
    if (iVar11 <= iVar25) goto LAB_0040cb6b;
    rvb->wds = 0;
    rvb->x[0] = 0;
    *expo = iVar11;
    goto LAB_0040d8e0;
  }
  if (iVar25 == 0) goto LAB_0040cb30;
  rvbits = iVar25 + rvbits;
  if (0 < rvbits) {
    __rshift_D2A(rvb,iVar11 - rve);
    goto LAB_0040cb30;
  }
  if (-2 < rvbits) {
    rvbits = 1;
    rvb->wds = 1;
    rvb->x[0] = 1;
    goto LAB_0040cb30;
  }
  rvb->wds = 0;
  rvb->x[0] = 0;
  *expo = iVar11;
  if (local_48 != 0) goto LAB_0040d8e0;
  uVar7 = (uint)(0 < rvb->wds) * 2 | 0x50;
  goto LAB_0040c858;
LAB_0040d6b8:
  irv = irv | local_4c;
LAB_0040d6d0:
  local_48 = iVar17;
  uVar21 = rvbits;
  if (local_94 == 0) {
LAB_0040d977:
    iVar6 = n - uVar21;
    local_94 = 0;
    if (iVar6 != 0) {
      if (iVar6 < 1) {
        __rshift_D2A(rvb,uVar21 - n);
      }
      else {
        rvb = __lshift_D2A(rvb,iVar6);
      }
      local_94 = 0;
      rve = rve - iVar6;
    }
  }
  goto LAB_0040d6e3;
  while (uVar7 = *pUVar14, pUVar14 = pUVar14 + 1, uVar7 == 0xffffffff) {
LAB_0040dd54:
    if (rvb->x + (rvbits >> 5) <= pUVar14) {
      if (((rvbits & 0x1fU) == 0) || ((-1 << (sbyte)(rvbits & 0x1fU) | *pUVar14) == 0xffffffff)) {
        rvb->wds = 1;
        rvb->x[0] = 1;
        rvbits = 1;
        rve = n + -1 + iVar11;
        irv = 0x21;
        uVar21 = local_94;
        goto LAB_0040d977;
      }
      break;
    }
  }
  irv = 0x11;
  if ((rvb->x[0] & 1) != 0) {
LAB_0040e042:
    rvb = __increment_D2A(rvb);
    uVar7 = 0x1f;
    if (rvb->x[rvb->wds + -1] != 0) {
      for (; rvb->x[rvb->wds + -1] >> uVar7 == 0; uVar7 = uVar7 - 1) {
      }
    }
    if ((-rvbits & 0x1fU) != (uVar7 ^ 0x1f)) {
      rvbits = rvbits + 1;
    }
    irv = 0x21;
    goto LAB_0040d6d0;
  }
LAB_0040d6e3:
  *expo = rve;
  __Bfree_D2A(b);
  __Bfree_D2A(local_9c);
  __Bfree_D2A(local_a0);
  __Bfree_D2A(p_Var18);
  __Bfree_D2A(p_Var12);
  if (fpi->emax < rve) {
    uVar7 = fpi->rounding & 3;
    if (uVar7 == 2) {
      if (local_68 == 0) goto LAB_0040da38;
    }
    else if (uVar7 == 3) {
      if (local_68 != 0) goto LAB_0040da38;
    }
    else if (uVar7 == 1) {
LAB_0040da38:
      irv = 0xa3;
      rvb->wds = 0;
      piVar9 = __errno();
      *piVar9 = 0x22;
      *expo = fpi->emax + 1;
      goto LAB_0040d7e8;
    }
    __Bfree_D2A(rvb);
    rvb = (__Bigint *)0x0;
    irv = 0x11;
    *expo = fpi->emax;
    uVar7 = fpi->nbits;
    iVar6 = (int)(uVar7 + 0x1f) >> 5;
    pUVar14 = bits + iVar6;
    if (bits < pUVar14) {
      memset(bits,0xff,iVar6 * 4);
    }
    uVar7 = uVar7 & 0x1f;
    if (uVar7 != 0) {
      pUVar14[-1] = pUVar14[-1] >> (0x20U - (char)uVar7 & 0x1f);
    }
  }
LAB_0040d7e8:
  if (local_94 != 0) {
    if (local_48 == 0) {
      uVar7 = (uint)(0 < rvb->wds) * 2 | irv & 0xfffffff8U;
      uVar21 = irv & 0x30;
      irv = uVar7;
      if (uVar21 != 0) {
LAB_0040c858:
        irv = uVar7 | 0x40;
        piVar9 = __errno();
        *piVar9 = 0x22;
      }
    }
    else {
LAB_0040d8e0:
      rvb->wds = 0;
      irv = 0x50;
      piVar9 = __errno();
      *piVar9 = 0x22;
    }
  }
LAB_0040c630:
  if (se != (char **)0x0) {
    *se = s;
  }
  if (local_68 != 0) {
    irv = irv | 8;
  }
LAB_0040c65b:
  if (rvb != (__Bigint *)0x0) {
    __copybits_D2A(bits,n,rvb);
    __Bfree_D2A(rvb);
  }
  return irv;
}



// --- Function: __sum_D2A @ 0040e090 ---

/* WARNING: Unknown calling convention */

__Bigint * __sum_D2A(__Bigint *a,__Bigint *b)

{
  ULong *pUVar1;
  ULong *pUVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  __Bigint *v;
  int iVar6;
  __Bigint *p_Var7;
  ULong *pUVar8;
  ULong *pUVar9;
  undefined2 *puVar10;
  int iVar11;
  ULong *pUVar12;
  uint uVar13;
  uint *puVar14;
  ULong *local_38;
  
                    /* Unresolved local var: __Bigint * c@[???]
                       Unresolved local var: ULong carry@[???]
                       Unresolved local var: ULong * xc@[???]
                       Unresolved local var: ULong * xa@[???]
                       Unresolved local var: ULong * xb@[???]
                       Unresolved local var: ULong * xe@[???]
                       Unresolved local var: ULong y@[???]
                       Unresolved local var: ULong z@[???] */
  p_Var7 = a;
  if (b->wds <= a->wds) {
    p_Var7 = b;
    b = a;
  }
  v = __Balloc_D2A(b->k);
  iVar6 = b->wds;
  pUVar1 = v->x;
  v->wds = iVar6;
  iVar3 = p_Var7->wds;
  pUVar2 = pUVar1 + iVar3;
  uVar13 = 0;
  pUVar8 = pUVar1;
  pUVar12 = b->x;
  local_38 = p_Var7->x;
  do {
    uVar4 = *pUVar12;
    pUVar9 = pUVar8 + 1;
    pUVar12 = pUVar12 + 1;
    uVar5 = *local_38;
    uVar13 = (uVar4 & 0xffff) + (uVar5 & 0xffff) + uVar13;
    *(short *)pUVar8 = (short)uVar13;
    uVar13 = (uVar5 >> 0x10) + (uVar4 >> 0x10) + (uVar13 >> 0x10);
    *(short *)((int)pUVar8 + 2) = (short)uVar13;
    uVar13 = uVar13 >> 0x10;
    pUVar8 = pUVar9;
    local_38 = local_38 + 1;
  } while (pUVar9 < pUVar2);
  iVar11 = ((int)pUVar2 + (-0x15 - (int)v) & 0xfffffffcU) + 4;
  if (pUVar2 < (undefined2 *)((int)v->x + 1U)) {
    iVar11 = 4;
  }
  puVar14 = (uint *)((int)b->x + iVar11);
  for (puVar10 = (undefined2 *)((int)pUVar1 + iVar11); puVar10 < pUVar2 + (iVar6 - iVar3);
      puVar10 = puVar10 + 2) {
    uVar4 = *puVar14;
    puVar14 = puVar14 + 1;
    uVar13 = (uVar4 & 0xffff) + uVar13;
    *puVar10 = (short)uVar13;
    uVar13 = (uVar4 >> 0x10) + (uVar13 >> 0x10);
    puVar10[1] = (short)uVar13;
    uVar13 = uVar13 >> 0x10;
  }
  p_Var7 = v;
  if (uVar13 != 0) {
    if (iVar6 == v->maxwds) {
      p_Var7 = __Balloc_D2A(v->k + 1);
      memcpy(&p_Var7->sign,&v->sign,v->wds * 4 + 8);
      __Bfree_D2A(v);
      iVar6 = p_Var7->wds;
    }
    p_Var7->wds = iVar6 + 1;
    p_Var7->x[iVar6] = 1;
  }
  return p_Var7;
}



// --- Function: strnlen @ 0040e220 ---

/* WARNING: Unknown calling convention */

size_t strnlen(char *s,size_t maxlen)

{
  char *pcVar1;
  size_t sVar2;
  
                    /* Unresolved local var: char * s2@[???] */
  sVar2 = 0;
  pcVar1 = s;
  if (maxlen != 0) {
    do {
      if (*pcVar1 == '\0') {
        return sVar2;
      }
      pcVar1 = pcVar1 + 1;
      sVar2 = (int)pcVar1 - (int)s;
    } while (sVar2 < maxlen);
  }
  return sVar2;
}



// --- Function: wcsnlen @ 0040e250 ---

/* WARNING: Unknown calling convention */

size_t wcsnlen(wchar_t *w,size_t ncnt)

{
  size_t sVar1;
  
                    /* Unresolved local var: size_t n@[???] */
  sVar1 = 0;
  if (ncnt != 0) {
    do {
      if (w[sVar1] == L'\0') {
        return sVar1;
      }
      sVar1 = sVar1 + 1;
    } while (ncnt != sVar1);
  }
  return ncnt;
}



// --- Function: __gethex_D2A @ 0040e280 ---

/* WARNING: Type propagation algorithm not settling */
/* WARNING: Unknown calling convention */

int __gethex_D2A(char **sp,FPI *fpi,long *expo,__Bigint **bp,int sign)

{
  byte bVar1;
  byte bVar2;
  byte *pbVar3;
  char *pcVar4;
  bool bVar5;
  undefined4 *puVar6;
  int iVar7;
  __Bigint *p_Var8;
  byte *pbVar9;
  byte *pbVar10;
  int *piVar11;
  byte bVar12;
  int iVar13;
  uint uVar14;
  uint uVar15;
  int iVar16;
  ULong UVar17;
  int iVar18;
  byte *pbVar19;
  byte *pbVar20;
  uint uVar21;
  uint k;
  bool bVar22;
  int local_38;
  ULong *local_34;
  ULong *local_30;
  int local_2c;
  byte *local_28;
  uint local_24;
  
                    /* Unresolved local var: __Bigint * b@[???]
                       Unresolved local var: uchar * decpt@[???]
                       Unresolved local var: uchar * s0@[???]
                       Unresolved local var: uchar * s@[???]
                       Unresolved local var: uchar * s1@[???]
                       Unresolved local var: int big@[???]
                       Unresolved local var: int esign@[???]
                       Unresolved local var: int havedig@[???]
                       Unresolved local var: int irv@[???]
                       Unresolved local var: int j@[???]
                       Unresolved local var: int k@[???]
                       Unresolved local var: int n@[???]
                       Unresolved local var: int n0@[???]
                       Unresolved local var: int nbits@[???]
                       Unresolved local var: int up@[???]
                       Unresolved local var: int zret@[???]
                       Unresolved local var: ULong L@[???]
                       Unresolved local var: ULong lostbits@[???]
                       Unresolved local var: ULong * x@[???]
                       Unresolved local var: long e@[???]
                       Unresolved local var: long e1@[???]
                       Unresolved local var: int i@[???]
                       Unresolved local var: uchar * decimalpoint@[???] */
  puVar6 = (undefined4 *)localeconv();
  pbVar3 = (byte *)*puVar6;
  if (__hexdig_D2A[0x30] == '\0') {
    __mingw_hexdig_init_D2A();
  }
  *bp = (__Bigint *)0x0;
  pcVar4 = *sp;
  bVar12 = pcVar4[2];
  if (bVar12 == 0x30) {
    pbVar20 = (byte *)(pcVar4 + 3);
    do {
      pbVar9 = pbVar20;
      bVar12 = *pbVar9;
      pbVar20 = pbVar9 + 1;
    } while (bVar12 == 0x30);
    local_34 = (ULong *)(pbVar9 + (-2 - (int)pcVar4));
  }
  else {
    local_34 = (ULong *)0x0;
    pbVar9 = (byte *)(pcVar4 + 2);
  }
  bVar1 = *pbVar3;
  pbVar20 = pbVar9;
  if (__hexdig_D2A[bVar12] == '\0') {
    iVar7 = 0;
    pbVar10 = pbVar9;
    bVar2 = bVar1;
    if (bVar1 != 0) {
      do {
        if (pbVar9[iVar7] != bVar2) goto LAB_0040e302;
        iVar7 = iVar7 + 1;
        bVar2 = pbVar3[iVar7];
      } while (bVar2 != 0);
      pbVar10 = pbVar9 + iVar7;
      bVar12 = *pbVar10;
      if (__hexdig_D2A[bVar12] != '\0') {
        pbVar9 = pbVar10;
        if (bVar12 != 0x30) {
          bVar22 = false;
LAB_0040e795:
          local_34 = (ULong *)0x1;
          pbVar20 = pbVar9;
          goto LAB_0040e448;
        }
        do {
          bVar12 = pbVar9[1];
          pbVar9 = pbVar9 + 1;
        } while (bVar12 == 0x30);
        bVar22 = __hexdig_D2A[bVar12] == '\0';
        if (!bVar22) goto LAB_0040e795;
        local_34 = (ULong *)0x1;
        pbVar20 = pbVar9;
        if (bVar12 == bVar1) goto LAB_0040e568;
        goto LAB_0040e464;
      }
    }
LAB_0040e302:
    if ((bVar12 & 0xdf) == 0x50) {
      local_38 = 0;
      bVar22 = true;
LAB_0040e588:
      bVar12 = pbVar10[1];
      if (bVar12 == 0x2b) {
        local_2c = 0;
LAB_0040e728:
        local_28 = pbVar10 + 2;
        bVar12 = pbVar10[2];
      }
      else {
        if (bVar12 == 0x2d) {
          local_2c = 1;
          goto LAB_0040e728;
        }
        local_28 = pbVar10 + 1;
        local_2c = 0;
      }
      bVar5 = false;
      pbVar9 = pbVar10;
      if ((byte)(__hexdig_D2A[bVar12] - 1) < 0x19) {
        local_24 = __hexdig_D2A[bVar12] - 0x10;
        pbVar9 = local_28 + 1;
        bVar12 = __hexdig_D2A[local_28[1]];
        if ((byte)(bVar12 - 1) < 0x19) {
          bVar5 = false;
          do {
            if (0x7ffffff < local_24) {
              bVar5 = true;
            }
            pbVar19 = pbVar9 + 1;
            local_24 = (bVar12 - 0x10) + local_24 * 10;
            pbVar9 = pbVar9 + 1;
            bVar12 = __hexdig_D2A[*pbVar19];
          } while ((byte)(bVar12 - 1) < 0x19);
        }
        uVar14 = -local_24;
        if (local_2c == 0) {
          uVar14 = local_24;
        }
        local_38 = local_38 + uVar14;
      }
    }
    else {
      bVar22 = true;
      bVar5 = false;
      local_38 = 0;
      local_2c = 0;
      pbVar9 = pbVar10;
    }
    pbVar19 = pbVar10;
    if (local_34 == (ULong *)0x0) {
      pbVar9 = pbVar20 + -1;
    }
LAB_0040e336:
    *sp = (char *)pbVar9;
    if (bVar22) {
      return 0;
    }
    if (bVar5) {
      iVar7 = fpi->rounding;
      if (local_2c != 0) {
        if (iVar7 == 2) {
          if (sign != 0) goto LAB_0040e846;
        }
        else if ((iVar7 != 3) || (sign == 0)) goto LAB_0040e846;
        p_Var8 = __Balloc_D2A(0);
        p_Var8->wds = 1;
        p_Var8->x[0] = 1;
        iVar7 = fpi->emin;
        goto LAB_0040e7e9;
      }
      if (iVar7 == 2) {
        if (sign != 0) goto LAB_0040e37e;
      }
      else if (iVar7 == 3) {
        if (sign == 0) goto LAB_0040e37e;
      }
      else if (iVar7 != 1) {
LAB_0040e37e:
        uVar14 = fpi->nbits & 0x1f;
        iVar16 = fpi->nbits >> 5;
        iVar18 = (iVar16 + 1) - (uint)(uVar14 == 0);
        iVar7 = 0;
        iVar13 = iVar18;
        while (iVar13 = iVar13 >> 1, iVar13 != 0) {
          iVar7 = iVar7 + 1;
        }
        p_Var8 = __Balloc_D2A(iVar7);
        *bp = p_Var8;
        p_Var8->wds = iVar18;
        if (0 < iVar16) {
          memset(p_Var8->x,0xff,iVar16 * 4);
          local_2c = iVar16;
        }
        if (iVar16 < iVar18) {
          p_Var8->x[local_2c] = 0x20 >> (0x20U - (char)uVar14 & 0x1f);
        }
        *expo = fpi->emin;
        return 0x11;
      }
      goto LAB_0040e8f5;
    }
  }
  else {
    local_34 = (ULong *)((int)local_34 + 1);
    pbVar10 = (byte *)0x0;
    bVar22 = false;
LAB_0040e448:
    do {
      pbVar19 = pbVar9 + 1;
      pbVar9 = pbVar9 + 1;
    } while (__hexdig_D2A[*pbVar19] != '\0');
    if (*pbVar19 == bVar1) {
      if (pbVar10 == (byte *)0x0) {
        bVar12 = pbVar3[1];
        if (bVar12 == 0) {
          iVar7 = 1;
        }
        else {
          iVar7 = 1;
          do {
            if (pbVar9[iVar7] != bVar12) {
              if ((*pbVar9 & 0xdf) != 0x50) {
                local_38 = 0;
                bVar5 = false;
                local_2c = 0;
                pbVar19 = pbVar9;
                goto LAB_0040e336;
              }
              local_38 = 0;
              pbVar10 = pbVar9;
              goto LAB_0040e588;
            }
            iVar7 = iVar7 + 1;
            bVar12 = pbVar3[iVar7];
          } while (bVar12 != 0);
        }
        pbVar10 = pbVar9 + iVar7;
        bVar12 = *pbVar10;
        pbVar9 = pbVar10;
        if (__hexdig_D2A[bVar12] != '\0') {
          do {
            bVar12 = pbVar9[1];
            pbVar9 = pbVar9 + 1;
          } while (__hexdig_D2A[bVar12] != '\0');
          goto LAB_0040e473;
        }
        local_38 = 0;
        pbVar19 = pbVar10;
      }
      else {
LAB_0040e568:
        bVar12 = *pbVar9;
        local_38 = ((int)pbVar10 - (int)pbVar9) * 4;
        pbVar19 = pbVar9;
      }
    }
    else {
LAB_0040e464:
      local_38 = 0;
      bVar12 = *pbVar9;
      pbVar19 = pbVar9;
      if (pbVar10 != (byte *)0x0) {
LAB_0040e473:
        local_38 = ((int)pbVar10 - (int)pbVar9) * 4;
        pbVar19 = pbVar9;
      }
    }
    pbVar10 = pbVar19;
    if ((bVar12 & 0xdf) == 0x50) goto LAB_0040e588;
    *sp = (char *)pbVar19;
    if (bVar22) {
      return 0;
    }
  }
  iVar7 = 0;
  for (pbVar9 = pbVar19 + (-1 - (int)pbVar20); 7 < (int)pbVar9; pbVar9 = (byte *)((int)pbVar9 >> 1))
  {
    iVar7 = iVar7 + 1;
  }
  p_Var8 = __Balloc_D2A(iVar7);
  local_30 = p_Var8->x;
  if (pbVar3[1] == 0) {
    local_2c = 0;
  }
  else {
    local_2c = strlen((char *)(pbVar3 + 2));
    local_2c = local_2c + 1;
  }
  local_34 = local_30;
  if (pbVar20 < pbVar19) {
    UVar17 = 0;
    iVar7 = 0;
    do {
      while( true ) {
        bVar12 = pbVar19[-1];
        pbVar9 = pbVar19 + -1;
        if (bVar12 == pbVar3[local_2c]) break;
        if (iVar7 == 0x20) {
          *local_34 = UVar17;
          bVar12 = pbVar19[-1];
          local_34 = local_34 + 1;
          UVar17 = 0;
          iVar13 = 4;
          iVar7 = 0;
        }
        else {
          iVar13 = iVar7 + 4;
        }
        UVar17 = UVar17 | (__hexdig_D2A[bVar12] & 0xf) << ((byte)iVar7 & 0x1f);
        pbVar19 = pbVar9;
        iVar7 = iVar13;
        if (pbVar9 <= pbVar20) goto LAB_0040e660;
      }
      pbVar19 = pbVar9 + -local_2c;
    } while (pbVar20 < pbVar19);
LAB_0040e660:
    uVar14 = 0x1f;
    if (UVar17 != 0) {
      for (; UVar17 >> uVar14 == 0; uVar14 = uVar14 - 1) {
      }
    }
    uVar14 = uVar14 ^ 0x1f;
  }
  else {
    UVar17 = 0;
    uVar14 = 0x20;
  }
  *local_34 = UVar17;
  iVar7 = (int)local_34 + (4 - (int)local_30) >> 2;
  p_Var8->wds = iVar7;
  iVar7 = iVar7 * 0x20 - uVar14;
  uVar14 = fpi->nbits;
  if ((int)uVar14 < iVar7) {
    iVar7 = iVar7 - uVar14;
    UVar17 = __any_on_D2A(p_Var8,iVar7);
    uVar15 = 0;
    if (UVar17 != 0) {
      iVar13 = iVar7 + -1;
      uVar15 = 1;
      if ((1 << ((byte)iVar13 & 0x1f) & local_30[iVar13 >> 5]) != 0) {
        if ((iVar13 == 0) || (UVar17 = __any_on_D2A(p_Var8,iVar13), UVar17 == 0)) {
          uVar15 = 2;
        }
        else {
          uVar15 = 3;
        }
      }
    }
    __rshift_D2A(p_Var8,iVar7);
    local_38 = local_38 + iVar7;
  }
  else {
    uVar15 = 0;
    if (iVar7 < (int)uVar14) {
      p_Var8 = __lshift_D2A(p_Var8,uVar14 - iVar7);
      local_38 = local_38 - (uVar14 - iVar7);
      local_30 = p_Var8->x;
    }
  }
  if (fpi->emax < local_38) {
LAB_0040e8ed:
    __Bfree_D2A(p_Var8);
LAB_0040e8f5:
    piVar11 = __errno();
    *piVar11 = 0x22;
    return 0xa3;
  }
  iVar7 = fpi->emin;
  if (local_38 < iVar7) {
    k = iVar7 - local_38;
    if ((int)uVar14 <= (int)k) {
      iVar13 = fpi->rounding;
      if (iVar13 == 2) {
        if (sign == 0) goto LAB_0040ea9c;
      }
      else if (iVar13 == 3) {
        if (sign != 0) goto LAB_0040ea9c;
      }
      else if ((iVar13 == 1) && (uVar14 == k)) {
        if (uVar14 != 1) {
          UVar17 = __any_on_D2A(p_Var8,uVar14 - 1);
          if (UVar17 == 0) goto LAB_0040e83e;
          iVar7 = fpi->emin;
        }
LAB_0040ea9c:
        p_Var8->wds = 1;
        *local_30 = 1;
LAB_0040e7e9:
        *bp = p_Var8;
        *expo = iVar7;
        piVar11 = __errno();
        *piVar11 = 0x22;
        return 0x62;
      }
LAB_0040e83e:
      __Bfree_D2A(p_Var8);
LAB_0040e846:
      piVar11 = __errno();
      *piVar11 = 0x22;
      return 0x50;
    }
    iVar7 = k - 1;
    if (uVar15 == 0) {
      if (iVar7 != 0) {
        uVar15 = __any_on_D2A(p_Var8,iVar7);
      }
    }
    else {
      uVar15 = 1;
    }
    if ((1 << ((byte)iVar7 & 0x1f) & local_30[iVar7 >> 5]) != 0) {
      uVar15 = uVar15 | 2;
    }
    uVar14 = uVar14 - k;
    uVar21 = 2;
    __rshift_D2A(p_Var8,k);
    local_38 = fpi->emin;
  }
  else {
    uVar21 = 1;
  }
  if (uVar15 == 0) goto LAB_0040e6ef;
  iVar7 = fpi->rounding;
  if (iVar7 == 2) {
    sign = 1 - sign;
joined_r0x0040ea07:
    if (sign != 0) {
      iVar7 = p_Var8->wds;
      p_Var8 = __increment_D2A(p_Var8);
      if (uVar21 == 2) {
        uVar21 = 0x22;
        if (fpi->nbits - 1U == uVar14) {
          uVar21 = ((1 << ((byte)uVar14 & 0x1f) & p_Var8->x[(int)uVar14 >> 5]) == 0) + 0x21;
        }
        goto LAB_0040e6ef;
      }
      if (iVar7 < p_Var8->wds) {
LAB_0040ea45:
        __rshift_D2A(p_Var8,1);
        local_38 = local_38 + 1;
        if (fpi->emax < local_38) goto LAB_0040e8ed;
      }
      else if ((uVar14 & 0x1f) != 0) {
        uVar15 = 0x1f;
        if (p_Var8->x[iVar7 + -1] != 0) {
          for (; p_Var8->x[iVar7 + -1] >> uVar15 == 0; uVar15 = uVar15 - 1) {
          }
        }
        if ((int)(uVar15 ^ 0x1f) < (int)(0x20 - (uVar14 & 0x1f))) goto LAB_0040ea45;
      }
      uVar21 = 0x21;
      goto LAB_0040e6ef;
    }
  }
  else {
    if (iVar7 == 3) goto joined_r0x0040ea07;
    if ((iVar7 == 1) && ((uVar15 & 2) != 0)) {
      sign = (uVar15 | *local_30) & 1;
      goto joined_r0x0040ea07;
    }
  }
  uVar21 = uVar21 | 0x10;
LAB_0040e6ef:
  *bp = p_Var8;
  *expo = local_38;
  return uVar21;
}



// --- Function: __mingw_hexdig_init_D2A @ 0040ec20 ---

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void __mingw_hexdig_init_D2A(void)

{
  byte bVar1;
  uint uVar2;
  byte *pbVar3;
  
                    /* Unresolved local var: int i@[???]
                       Unresolved local var: int j@[???] */
  uVar2 = 0x30;
  pbVar3 = &DAT_00411b21;
  do {
    __hexdig_D2A[uVar2] = (char)pbVar3 + 0xef;
    bVar1 = *pbVar3;
    uVar2 = (uint)bVar1;
    pbVar3 = pbVar3 + 1;
  } while (bVar1 != 0);
                    /* Unresolved local var: int i@[???]
                       Unresolved local var: int j@[???] */
  uVar2 = 0x61;
  pbVar3 = &DAT_00411b2c;
  do {
    __hexdig_D2A[uVar2] = (char)pbVar3 + 0xee;
    bVar1 = *pbVar3;
    uVar2 = (uint)bVar1;
    pbVar3 = pbVar3 + 1;
  } while (bVar1 != 0);
                    /* Unresolved local var: int i@[???]
                       Unresolved local var: int j@[???] */
  uVar2 = 0x41;
  pbVar3 = &DAT_00411b33;
  do {
    __hexdig_D2A[uVar2] = (char)pbVar3 + 0xe7;
    bVar1 = *pbVar3;
    uVar2 = (uint)bVar1;
    pbVar3 = pbVar3 + 1;
  } while (bVar1 != 0);
  return;
}



// --- Function: __hexnan_D2A @ 0040eca0 ---

/* WARNING: Type propagation algorithm not settling */
/* WARNING: Unknown calling convention */

int __hexnan_D2A(char **sp,FPI *fpi,ULong *x0)

{
  byte *pbVar1;
  uint *puVar2;
  char cVar3;
  byte bVar4;
  uint uVar5;
  uint uVar6;
  char *pcVar7;
  void *pvVar8;
  uint uVar9;
  size_t sVar10;
  uint *puVar11;
  char *pcVar12;
  uint *puVar13;
  int iVar14;
  uint *puVar15;
  uint *local_40;
  int local_3c;
  uint *local_38;
  int local_34;
  uint *local_24;
  
                    /* Unresolved local var: ULong c@[???]
                       Unresolved local var: ULong h@[???]
                       Unresolved local var: ULong * x@[???]
                       Unresolved local var: ULong * x1@[???]
                       Unresolved local var: ULong * xe@[???]
                       Unresolved local var: char * s@[???]
                       Unresolved local var: int havedig@[???]
                       Unresolved local var: int hd0@[???]
                       Unresolved local var: int i@[???]
                       Unresolved local var: int nbits@[???] */
  if (__hexdig_D2A[0x30] == '\0') {
    __mingw_hexdig_init_D2A();
  }
  uVar5 = fpi->nbits & 0x1f;
  puVar11 = x0 + (fpi->nbits >> 5);
  if (uVar5 == 0) {
    puVar13 = puVar11 + -1;
    local_24 = puVar11;
  }
  else {
    local_24 = puVar11 + 1;
    puVar13 = puVar11;
  }
  local_24[-1] = 0;
  pcVar12 = *sp;
  bVar4 = pcVar12[1];
  if (bVar4 != 0) {
    do {
      if (0x20 < bVar4) {
        if (((bVar4 == 0x30) && ((pcVar12[2] & 0xdfU) == 0x58)) &&
           (uVar9 = (uint)(byte)pcVar12[3], 0x20 < (byte)pcVar12[3])) {
          pcVar7 = pcVar12 + 3;
          pcVar12 = pcVar12 + 2;
          goto LAB_0040ed3f;
        }
        break;
      }
      bVar4 = pcVar12[2];
      pcVar12 = pcVar12 + 1;
    } while (bVar4 != 0);
    uVar9 = (uint)(byte)pcVar12[1];
    pcVar7 = pcVar12 + 1;
    if (uVar9 != 0) {
LAB_0040ed3f:
      local_34 = 0;
                    /* Unresolved local var: int j@[???] */
      local_3c = 0;
      iVar14 = 0;
      local_40 = puVar13;
      local_38 = puVar13;
LAB_0040ed60:
      do {
        bVar4 = __hexdig_D2A[uVar9];
        if (bVar4 == 0) {
          if (0x20 < uVar9) {
            if ((uVar9 != 0x29) || (local_3c == 0)) {
              do {
                pcVar7 = pcVar7 + 1;
                if (uVar9 == 0x29) {
                  *sp = pcVar7;
                  return 4;
                }
                uVar9 = (uint)*pcVar7;
              } while (uVar9 != 0);
              return 4;
            }
            *sp = pcVar12 + 2;
            if (local_38 <= local_40) goto joined_r0x0040ee3c;
            goto LAB_0040ee2b;
          }
          puVar11 = local_40;
          if (local_3c <= local_34) {
LAB_0040ef42:
            bVar4 = pcVar7[1];
            while (bVar4 < 0x21) {
              pbVar1 = (byte *)(pcVar7 + 2);
              pcVar7 = pcVar7 + 1;
              bVar4 = *pbVar1;
            }
            local_40 = puVar11;
            if (((bVar4 != 0x30) || ((pcVar7[2] & 0xdfU) != 0x58)) ||
               (uVar9 = (uint)(byte)pcVar7[3], (byte)pcVar7[3] < 0x21)) goto LAB_0040eef9;
            pcVar12 = pcVar7 + 2;
            pcVar7 = pcVar7 + 3;
            goto LAB_0040ed60;
          }
          if ((local_40 < local_38) && (iVar14 < 8)) {
            cVar3 = '\b' - (char)iVar14;
            uVar9 = *local_40;
            do {
              puVar15 = puVar11 + 1;
              uVar6 = puVar11[1] >> (cVar3 * '\x04' & 0x1fU);
              *puVar11 = uVar9 | puVar11[1] << (cVar3 * -4 + 0x20U & 0x1f);
              *puVar15 = uVar6;
              uVar9 = uVar6;
              puVar11 = puVar15;
            } while (puVar15 < local_38);
          }
          if (x0 < local_40) {
            puVar11 = local_40 + -1;
            local_40[-1] = 0;
            iVar14 = 0;
            local_34 = local_3c;
            local_38 = puVar11;
            goto LAB_0040ef42;
          }
          bVar4 = pcVar7[1];
          iVar14 = 8;
          pcVar12 = pcVar7;
        }
        else {
          iVar14 = iVar14 + 1;
          local_3c = local_3c + 1;
          if (iVar14 < 9) {
            uVar9 = *local_40 << 4;
          }
          else {
            if (local_40 <= x0) goto LAB_0040eef9;
            local_40[-1] = 0;
            uVar9 = 0;
            local_40 = local_40 + -1;
            iVar14 = 1;
          }
          *local_40 = bVar4 & 0xf | uVar9;
LAB_0040eef9:
          bVar4 = pcVar7[1];
          pcVar12 = pcVar7;
        }
        uVar9 = (uint)bVar4;
        pcVar7 = pcVar12 + 1;
      } while (uVar9 != 0);
      if (local_3c != 0) {
        if (local_40 < local_38) {
LAB_0040ee2b:
          if (iVar14 < 8) {
                    /* Unresolved local var: int j@[???] */
            cVar3 = '\b' - (char)iVar14;
            local_3c._0_1_ = cVar3 * -4 + 0x20;
            uVar9 = *local_40;
            puVar11 = local_40;
            do {
              puVar15 = puVar11 + 1;
              *puVar11 = uVar9 | puVar11[1] << ((byte)local_3c & 0x1f);
              uVar9 = puVar11[1] >> (cVar3 * '\x04' & 0x1fU);
              *puVar15 = uVar9;
              puVar11 = puVar15;
            } while (puVar15 < local_38);
          }
        }
joined_r0x0040ee3c:
        puVar11 = local_40;
        puVar15 = x0;
        if (x0 < local_40) {
          do {
            puVar2 = puVar11 + 1;
            *puVar15 = *puVar11;
            puVar11 = puVar2;
            puVar15 = puVar15 + 1;
          } while (puVar2 <= puVar13);
          iVar14 = ((int)puVar13 - (int)local_40 & 0xfffffffcU) + 4;
          if ((int)puVar13 + 1U < (int)local_40 + 1U) {
            iVar14 = 4;
          }
          pvVar8 = (void *)(iVar14 + (int)x0);
          sVar10 = ((int)puVar13 - (int)pvVar8 & 0xfffffffcU) + 4;
          if ((int)puVar13 + 1U < (int)pvVar8 + 1U) {
            sVar10 = 4;
          }
          memset(pvVar8,0,sVar10);
          uVar9 = local_24[-1];
        }
        else {
          uVar9 = local_24[-1];
          if (uVar5 != 0) {
            uVar9 = uVar9 & 0xffffffffU >> (0x20U - (char)uVar5 & 0x1f);
            local_24[-1] = uVar9;
          }
        }
        while( true ) {
          if (uVar9 != 0) {
            return 5;
          }
          if (x0 == puVar13) break;
          uVar9 = puVar13[-1];
          puVar13 = puVar13 + -1;
        }
        *puVar13 = 1;
        return 5;
      }
    }
  }
  return 4;
}



// --- Function: __s2b_D2A @ 0040f0d0 ---

/* WARNING: Unknown calling convention */

__Bigint * __s2b_D2A(char *s,int nd0,int nd,ULong y9,int dplen)

{
  char cVar1;
  int iVar2;
  __Bigint *b;
  int k;
  char *pcVar3;
  char *pcVar4;
  
                    /* Unresolved local var: __Bigint * b@[???]
                       Unresolved local var: int i@[???]
                       Unresolved local var: int k@[???]
                       Unresolved local var: long x@[???]
                       Unresolved local var: long y@[???] */
  if (nd < 10) {
    k = 0;
  }
  else {
    iVar2 = 1;
    k = 0;
    do {
      iVar2 = iVar2 * 2;
      k = k + 1;
    } while (iVar2 < (nd + 8) / 9);
  }
  b = __Balloc_D2A(k);
  b->wds = 1;
  b->x[0] = y9;
  if (nd0 < 10) {
    pcVar3 = s + 9;
    nd0 = 9;
  }
  else {
    pcVar4 = s + 9;
    pcVar3 = s + nd0;
    do {
      cVar1 = *pcVar4;
      pcVar4 = pcVar4 + 1;
      b = __multadd_D2A(b,10,cVar1 + -0x30);
    } while (pcVar3 != pcVar4);
  }
  pcVar3 = pcVar3 + dplen;
  if (nd0 < nd) {
    pcVar4 = pcVar3 + (nd - nd0);
    do {
      cVar1 = *pcVar3;
      pcVar3 = pcVar3 + 1;
      b = __multadd_D2A(b,10,cVar1 + -0x30);
    } while (pcVar4 != pcVar3);
  }
  return b;
}



// --- Function: __ratio_D2A @ 0040f1c0 ---

/* WARNING: Unknown calling convention */

double __ratio_D2A(__Bigint *a,__Bigint *b)

{
  int iVar1;
  double dVar2;
  double dVar3;
  undefined4 local_3c;
  int iStack_38;
  undefined4 local_34;
  int iStack_30;
  int ka;
  int kb;
  
                    /* Unresolved local var: _dbl_union da@[???]
                       Unresolved local var: _dbl_union db@[???]
                       Unresolved local var: int k@[???] */
  dVar2 = __b2d_D2A(a,&ka);
  local_3c = SUB84(dVar2,0);
  iStack_38 = (int)((ulonglong)dVar2 >> 0x20);
  dVar3 = __b2d_D2A(b,&kb);
  local_34 = SUB84(dVar3,0);
  iVar1 = ((a->wds - b->wds) * 0x20 + ka) - kb;
  if (0 < iVar1) {
    return (double)CONCAT44(iVar1 * 0x100000 + iStack_38,local_3c) / dVar3;
  }
  iStack_30 = (int)((ulonglong)dVar3 >> 0x20);
  return dVar2 / (double)CONCAT44(iStack_30 + iVar1 * -0x100000,local_34);
}



// --- Function: __match_D2A @ 0040f280 ---

/* WARNING: Unknown calling convention */

int __match_D2A(char **sp,char *t)

{
  char cVar1;
  int iVar2;
  char *pcVar3;
  
                    /* Unresolved local var: int c@[???]
                       Unresolved local var: int d@[???]
                       Unresolved local var: char * s@[???] */
  pcVar3 = *sp;
  do {
    cVar1 = *t;
    t = t + 1;
    pcVar3 = pcVar3 + 1;
    if (cVar1 == 0) {
      *sp = pcVar3;
      return 1;
    }
    iVar2 = (int)*pcVar3;
    if (iVar2 - 0x41U < 0x1a) {
      iVar2 = iVar2 + 0x20;
    }
  } while (iVar2 == cVar1);
  return 0;
}



// --- Function: __copybits_D2A @ 0040f2d0 ---

/* WARNING: Unknown calling convention */

void __copybits_D2A(ULong *c,int n,__Bigint *b)

{
  ULong *pUVar1;
  ULong *pUVar2;
  ULong *pUVar3;
  ULong *pUVar4;
  ULong *pUVar5;
  
                    /* Unresolved local var: ULong * ce@[???]
                       Unresolved local var: ULong * x@[???]
                       Unresolved local var: ULong * xe@[???] */
  pUVar4 = b->x;
  pUVar2 = c + (n + -1 >> 5) + 1;
  pUVar1 = pUVar4 + b->wds;
  pUVar5 = c;
  if (pUVar4 < pUVar1) {
    do {
      pUVar3 = pUVar4 + 1;
      *pUVar5 = *pUVar4;
      pUVar4 = pUVar3;
      pUVar5 = pUVar5 + 1;
    } while (pUVar3 < pUVar1);
    c = (ULong *)((int)c + ((int)pUVar1 + (-0x15 - (int)b) & 0xfffffffcU) + 4);
  }
  if (pUVar2 <= c) {
    return;
  }
  memset(c,0,((int)pUVar2 + (-1 - (int)c) & 0xfffffffcU) + 4);
  return;
}



// --- Function: __any_on_D2A @ 0040f350 ---

/* WARNING: Unknown calling convention */

ULong __any_on_D2A(__Bigint *b,int k)

{
  ULong *pUVar1;
  int *piVar2;
  int iVar3;
  ULong *pUVar4;
  sbyte sVar5;
  int iVar6;
  
                    /* Unresolved local var: int n@[???]
                       Unresolved local var: int nwds@[???]
                       Unresolved local var: ULong * x@[???]
                       Unresolved local var: ULong * x0@[???]
                       Unresolved local var: ULong x1@[???]
                       Unresolved local var: ULong x2@[???] */
  iVar3 = b->wds;
  pUVar1 = b->x;
  iVar6 = k >> 5;
  if (iVar3 < iVar6) {
    pUVar4 = pUVar1 + iVar3;
  }
  else {
    pUVar4 = pUVar1 + iVar6;
    if (((iVar6 < iVar3) && ((k & 0x1fU) != 0)) &&
       (sVar5 = (sbyte)(k & 0x1fU), *pUVar4 != (*pUVar4 >> sVar5) << sVar5)) {
      return 1;
    }
  }
  do {
    if (pUVar4 <= pUVar1) {
      return 0;
    }
    piVar2 = (int *)(pUVar4 + -1);
    pUVar4 = pUVar4 + -1;
  } while (*piVar2 == 0);
  return 1;
}



// --- Function: _lock_file @ 0040f3c0 ---

/* WARNING: Unknown calling convention */

void _lock_file(FILE *pf)

{
  FILE *pFVar1;
  
  pFVar1 = __acrt_iob_func(0);
  if (pFVar1 <= pf) {
    pFVar1 = __acrt_iob_func(0x13);
    if (pf <= pFVar1) {
      pFVar1 = __acrt_iob_func(0);
      __lock(((int)pf - (int)pFVar1 >> 5) + 0x10);
      pf->_flag = pf->_flag | 0x8000;
      return;
    }
  }
  EnterCriticalSection((LPCRITICAL_SECTION)(pf + 1));
  return;
}



// --- Function: _unlock_file @ 0040f430 ---

/* WARNING: Unknown calling convention */

void _unlock_file(FILE *pf)

{
  FILE *pFVar1;
  
  pFVar1 = __acrt_iob_func(0);
  if (pFVar1 <= pf) {
    pFVar1 = __acrt_iob_func(0x13);
    if (pf <= pFVar1) {
      pf->_flag = pf->_flag & 0xffff7fff;
      pFVar1 = __acrt_iob_func(0);
      __unlock(((int)pf - (int)pFVar1 >> 5) + 0x10);
      return;
    }
  }
  LeaveCriticalSection((LPCRITICAL_SECTION)(pf + 1));
  return;
}



// --- Function: mingw_get_invalid_parameter_handler @ 0040f4a0 ---

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

_invalid_parameter_handler mingw_get_invalid_parameter_handler(void)

{
  return handler;
}



// --- Function: mingw_set_invalid_parameter_handler @ 0040f4b0 ---

/* WARNING: Unknown calling convention */

_invalid_parameter_handler
mingw_set_invalid_parameter_handler(_invalid_parameter_handler new_handler)

{
  _invalid_parameter_handler p_Var1;
  
  p_Var1 = handler;
  LOCK();
  handler = new_handler;
  UNLOCK();
  return p_Var1;
}



// --- Function: __acrt_iob_func @ 0040f4c0 ---

/* WARNING: Unknown calling convention */

FILE * __acrt_iob_func(uint index)

{
  return (FILE *)(_iob_exref + index * 0x20);
}



// --- Function: __wcrtomb_cp @ 0040f4d0 ---

/* WARNING: Unknown calling convention */

int __wcrtomb_cp(char *dst,wchar_t wc,uint cp,uint mb_max)

{
  int iVar1;
  int *piVar2;
  wchar_t local_20 [8];
  int invalid_char;
  
  local_20[0] = wc;
  if (cp == 0) {
    if (0xff < (ushort)wc) {
LAB_0040f558:
      piVar2 = __errno();
      *piVar2 = 0x2a;
      return -1;
    }
    *dst = (char)wc;
    iVar1 = 1;
  }
  else {
                    /* Unresolved local var: int size@[???] */
    invalid_char = 0;
    iVar1 = WideCharToMultiByte(cp,0,local_20,1,dst,mb_max,(LPCSTR)0x0,&invalid_char);
    if ((iVar1 == 0) || (invalid_char != 0)) goto LAB_0040f558;
  }
  return iVar1;
}



// --- Function: wcrtomb @ 0040f570 ---

/* WARNING: Unknown calling convention */

size_t wcrtomb(char *dst,wchar_t wc,mbstate_t *ps)

{
  uint mb_max;
  uint cp;
  size_t sVar1;
  char byte_bucket [5];
  
                    /* Unresolved local var: char * tmp_dst@[???] */
  if (dst == (char *)0x0) {
    dst = byte_bucket;
  }
  mb_max = ___mb_cur_max_func();
  cp = ___lc_codepage_func();
  sVar1 = __wcrtomb_cp(dst,wc,cp,mb_max);
  return sVar1;
}



// --- Function: wcsrtombs @ 0040f5c0 ---

/* WARNING: Unknown calling convention */

size_t wcsrtombs(char *dst,wchar_t **src,size_t len,mbstate_t *ps)

{
  uint cp;
  uint mb_max;
  int iVar1;
  int iVar2;
  wchar_t *pwVar3;
  uint uVar4;
  char cStack_22;
  char byte_bucket [5];
  
                    /* Unresolved local var: int ret@[???]
                       Unresolved local var: size_t n@[???]
                       Unresolved local var: uint cp@[???]
                       Unresolved local var: uint mb_max@[???]
                       Unresolved local var: wchar_t * pwc@[???] */
  cp = ___lc_codepage_func();
  mb_max = ___mb_cur_max_func();
  pwVar3 = *src;
  if (pwVar3 == (wchar_t *)0x0) {
    return 0;
  }
  if (dst == (char *)0x0) {
    iVar1 = 0;
    while( true ) {
      iVar2 = __wcrtomb_cp(byte_bucket,*pwVar3,cp,mb_max);
      if (iVar2 < 1) {
        return 0xffffffff;
      }
      iVar1 = iVar1 + iVar2;
      if (byte_bucket[iVar2 + -1] == '\0') break;
      pwVar3 = pwVar3 + 1;
    }
    return iVar1 - 1;
  }
  uVar4 = 0;
  if (len != 0) {
    uVar4 = 0;
    do {
      iVar1 = __wcrtomb_cp(dst,*pwVar3,cp,mb_max);
      if (iVar1 < 1) {
        return 0xffffffff;
      }
      dst = dst + iVar1;
      uVar4 = uVar4 + iVar1;
      if (dst[-1] == '\0') {
        *src = (wchar_t *)0x0;
        return uVar4 - 1;
      }
      pwVar3 = pwVar3 + 1;
    } while (uVar4 < len);
  }
  *src = pwVar3;
  return uVar4;
}



// --- Function: __mbrtowc_cp @ 0040f6f0 ---

/* WARNING: Unknown calling convention */

int __mbrtowc_cp(wchar_t *pwc,char *s,size_t n,mbstate_t *ps,uint cp,uint mb_max)

{
  BYTE TestChar;
  BOOL BVar1;
  int iVar2;
  int *piVar3;
  anon_union_4_2_626584ff shift_state;
  
  if (s == (char *)0x0) {
    return 0;
  }
  if (n == 0) {
    return -2;
  }
  shift_state.val = *ps;
  TestChar = *s;
  *ps = 0;
  if (TestChar == '\0') {
    *pwc = L'\0';
    return 0;
  }
  if (mb_max < 2) {
LAB_0040f7a8:
    if (cp == 0) {
      *pwc = (ushort)(byte)*s;
      return 1;
    }
    iVar2 = MultiByteToWideChar(cp,8,s,1,pwc,1);
    if (iVar2 != 0) {
      return 1;
    }
  }
  else {
    if (shift_state.mbcs[0] == '\0') {
      BVar1 = IsDBCSLeadByteEx(cp,TestChar);
      if (BVar1 == 0) goto LAB_0040f7a8;
      if (n == 1) {
        *(char *)ps = *s;
        return -2;
      }
    }
    else {
      shift_state.val._2_2_ = (undefined2)((uint)shift_state >> 0x10);
      shift_state.mbcs[1] = TestChar;
      s = (char *)&shift_state;
    }
    iVar2 = MultiByteToWideChar(cp,8,s,2,pwc,1);
    if (iVar2 != 0) {
      return 2;
    }
  }
  piVar3 = __errno();
  *piVar3 = 0x2a;
  return -1;
}



// --- Function: mbrtowc @ 0040f870 ---

/* WARNING: Unknown calling convention */

size_t mbrtowc(wchar_t *pwc,char *s,size_t n,mbstate_t *ps)

{
  uint mb_max;
  uint cp;
  size_t sVar1;
  wchar_t byte_bucket;
  
                    /* Unresolved local var: wchar_t * dst@[???] */
  byte_bucket = L'\0';
  if (pwc == (wchar_t *)0x0) {
    pwc = &byte_bucket;
  }
  mb_max = ___mb_cur_max_func();
  cp = ___lc_codepage_func();
  if (ps == (mbstate_t *)0x0) {
    ps = &mbrtowc::internal_mbstate;
  }
  sVar1 = __mbrtowc_cp(pwc,s,n,ps,cp,mb_max);
  return sVar1;
}



// --- Function: mbsrtowcs @ 0040f8d0 ---

/* WARNING: Unknown calling convention */

size_t mbsrtowcs(wchar_t *dst,char **src,size_t len,mbstate_t *ps)

{
  mbstate_t *ps_00;
  uint cp;
  size_t n;
  char *s;
  int iVar1;
  uint uVar2;
  size_t sVar3;
  wchar_t byte_bucket;
  
                    /* Unresolved local var: int ret@[???]
                       Unresolved local var: size_t n@[???]
                       Unresolved local var: mbstate_t * internal_ps@[???]
                       Unresolved local var: uint cp@[???]
                       Unresolved local var: uint mb_max@[???] */
  ps_00 = &mbsrtowcs::internal_mbstate;
  if (ps != (mbstate_t *)0x0) {
    ps_00 = ps;
  }
  cp = ___lc_codepage_func();
  n = ___mb_cur_max_func();
  if ((src == (char **)0x0) || (s = *src, s == (char *)0x0)) {
    return 0;
  }
  if (dst == (wchar_t *)0x0) {
    byte_bucket = L'\0';
    sVar3 = 0;
    while (iVar1 = __mbrtowc_cp(&byte_bucket,s + sVar3,n,ps_00,cp,n), 0 < iVar1) {
      sVar3 = sVar3 + iVar1;
      s = *src;
    }
    return sVar3;
  }
  uVar2 = 0;
  if (len != 0) {
    do {
      iVar1 = __mbrtowc_cp(dst,s,len - uVar2,ps_00,cp,n);
      if (iVar1 < 1) {
        if (len <= uVar2) {
          return uVar2;
        }
        if (iVar1 != 0) {
          return uVar2;
        }
        *src = (char *)0x0;
        return uVar2;
      }
      uVar2 = uVar2 + iVar1;
      dst = dst + 1;
      s = *src + iVar1;
      *src = s;
    } while (uVar2 < len);
  }
  return uVar2;
}



// --- Function: mbrlen @ 0040fa10 ---

/* WARNING: Unknown calling convention */

size_t mbrlen(char *s,size_t n,mbstate_t *ps)

{
  uint mb_max;
  uint cp;
  size_t sVar1;
  wchar_t byte_bucket;
  
  byte_bucket = L'\0';
  mb_max = ___mb_cur_max_func();
  cp = ___lc_codepage_func();
  if (ps == (mbstate_t *)0x0) {
    ps = &mbrlen::s_mbstate;
  }
  sVar1 = __mbrtowc_cp(&byte_bucket,s,n,ps,cp,mb_max);
  return sVar1;
}



// --- Function: abort @ 0040fad8 ---

/* abort */

void __cdecl abort(void)

{
                    /* WARNING: Could not recover jumptable at 0x0040fad8. Too many branches */
                    /* WARNING: Subroutine does not return */
                    /* WARNING: Treating indirect jump as call */
  abort();
  return;
}



// --- Function: calloc @ 0040fae0 ---

/* calloc */

void __cdecl calloc(size_t param_1,size_t param_2)

{
                    /* WARNING: Could not recover jumptable at 0x0040fae0. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  calloc(param_1,param_2);
  return;
}



// --- Function: exit @ 0040fae8 ---

/* exit */

void __cdecl exit(int param_1)

{
                    /* WARNING: Could not recover jumptable at 0x0040fae8. Too many branches */
                    /* WARNING: Subroutine does not return */
                    /* WARNING: Treating indirect jump as call */
  exit(param_1);
  return;
}



// --- Function: fprintf @ 0040faf0 ---

/* fprintf */

void __cdecl fprintf(FILE *param_1,char *param_2)

{
                    /* WARNING: Could not recover jumptable at 0x0040faf0. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  fprintf(param_1,param_2);
  return;
}



// --- Function: fputc @ 0040faf8 ---

/* fputc */

void __cdecl fputc(int param_1,FILE *param_2)

{
                    /* WARNING: Could not recover jumptable at 0x0040faf8. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  fputc(param_1,param_2);
  return;
}



// --- Function: free @ 0040fb00 ---

/* free */

void __cdecl free(void *param_1)

{
                    /* WARNING: Could not recover jumptable at 0x0040fb00. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  free(param_1);
  return;
}



// --- Function: fwrite @ 0040fb08 ---

/* fwrite */

void __cdecl fwrite(void *param_1,size_t param_2,size_t param_3,FILE *param_4)

{
                    /* WARNING: Could not recover jumptable at 0x0040fb08. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  fwrite(param_1,param_2,param_3,param_4);
  return;
}



// --- Function: getc @ 0040fb10 ---

/* getc */

void __cdecl getc(FILE *param_1)

{
                    /* WARNING: Could not recover jumptable at 0x0040fb10. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  getc(param_1);
  return;
}



// --- Function: getchar @ 0040fb18 ---

/* getchar */

void __cdecl getchar(void)

{
                    /* WARNING: Could not recover jumptable at 0x0040fb18. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  getchar();
  return;
}



// --- Function: islower @ 0040fb20 ---

/* islower */

void __cdecl islower(int param_1)

{
                    /* WARNING: Could not recover jumptable at 0x0040fb20. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  islower(param_1);
  return;
}



// --- Function: isspace @ 0040fb28 ---

/* isspace */

void __cdecl isspace(int param_1)

{
                    /* WARNING: Could not recover jumptable at 0x0040fb28. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  isspace(param_1);
  return;
}



// --- Function: isupper @ 0040fb30 ---

/* isupper */

void __cdecl isupper(int param_1)

{
                    /* WARNING: Could not recover jumptable at 0x0040fb30. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  isupper(param_1);
  return;
}



// --- Function: isxdigit @ 0040fb38 ---

/* isxdigit */

void __cdecl isxdigit(int param_1)

{
                    /* WARNING: Could not recover jumptable at 0x0040fb38. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  isxdigit(param_1);
  return;
}



// --- Function: localeconv @ 0040fb40 ---

/* localeconv */

void __cdecl localeconv(void)

{
                    /* WARNING: Could not recover jumptable at 0x0040fb40. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  localeconv();
  return;
}



// --- Function: malloc @ 0040fb48 ---

/* malloc */

void __cdecl malloc(size_t param_1)

{
                    /* WARNING: Could not recover jumptable at 0x0040fb48. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  malloc(param_1);
  return;
}



// --- Function: memcpy @ 0040fb50 ---

/* memcpy */

void __cdecl memcpy(void *param_1,void *param_2,size_t param_3)

{
                    /* WARNING: Could not recover jumptable at 0x0040fb50. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  memcpy(param_1,param_2,param_3);
  return;
}



// --- Function: memset @ 0040fb58 ---

/* memset */

void __cdecl memset(void *param_1,int param_2,size_t param_3)

{
                    /* WARNING: Could not recover jumptable at 0x0040fb58. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  memset(param_1,param_2,param_3);
  return;
}



// --- Function: putchar @ 0040fb60 ---

/* putchar */

void __cdecl putchar(int param_1)

{
                    /* WARNING: Could not recover jumptable at 0x0040fb60. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  putchar(param_1);
  return;
}



// --- Function: realloc @ 0040fb68 ---

/* realloc */

void __cdecl realloc(void *param_1,size_t param_2)

{
                    /* WARNING: Could not recover jumptable at 0x0040fb68. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  realloc(param_1,param_2);
  return;
}



// --- Function: signal @ 0040fb70 ---

/* signal */

void __cdecl signal(int param_1)

{
                    /* WARNING: Could not recover jumptable at 0x0040fb70. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  signal(param_1);
  return;
}



// --- Function: strerror @ 0040fb78 ---

/* strerror */

void __cdecl strerror(int param_1)

{
                    /* WARNING: Could not recover jumptable at 0x0040fb78. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  strerror(param_1);
  return;
}



// --- Function: strlen @ 0040fb80 ---

/* strlen */

void __cdecl strlen(char *param_1)

{
                    /* WARNING: Could not recover jumptable at 0x0040fb80. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  strlen(param_1);
  return;
}



// --- Function: strncmp @ 0040fb88 ---

/* strncmp */

void __cdecl strncmp(char *param_1,char *param_2,size_t param_3)

{
                    /* WARNING: Could not recover jumptable at 0x0040fb88. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  strncmp(param_1,param_2,param_3);
  return;
}



// --- Function: strtol @ 0040fb90 ---

/* strtol */

void __cdecl strtol(char *param_1,char **param_2,int param_3)

{
                    /* WARNING: Could not recover jumptable at 0x0040fb90. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  strtol(param_1,param_2,param_3);
  return;
}



// --- Function: strtoul @ 0040fb98 ---

/* strtoul */

void __cdecl strtoul(char *param_1,char **param_2,int param_3)

{
                    /* WARNING: Could not recover jumptable at 0x0040fb98. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  strtoul(param_1,param_2,param_3);
  return;
}



// --- Function: tolower @ 0040fba0 ---

/* tolower */

void __cdecl tolower(int param_1)

{
                    /* WARNING: Could not recover jumptable at 0x0040fba0. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  tolower(param_1);
  return;
}



// --- Function: ungetc @ 0040fba8 ---

/* ungetc */

void __cdecl ungetc(int param_1,FILE *param_2)

{
                    /* WARNING: Could not recover jumptable at 0x0040fba8. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  ungetc(param_1,param_2);
  return;
}



// --- Function: vfprintf @ 0040fbb0 ---

/* vfprintf */

void __cdecl vfprintf(FILE *param_1,char *param_2,va_list param_3)

{
                    /* WARNING: Could not recover jumptable at 0x0040fbb0. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  vfprintf(param_1,param_2,param_3);
  return;
}



// --- Function: wcslen @ 0040fbb8 ---

/* wcslen */

void __cdecl wcslen(wchar_t *param_1)

{
                    /* WARNING: Could not recover jumptable at 0x0040fbb8. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  wcslen(param_1);
  return;
}



// --- Function: msvcrt___lc_codepage_func @ 0040fbc0 ---

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

uint msvcrt___lc_codepage_func(void)

{
  return *msvcrt__lc_codepage;
}



// --- Function: setlocale_codepage_hack @ 0040fbd0 ---

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

uint setlocale_codepage_hack(void)

{
  char *pcVar1;
  int iVar2;
  uint uVar3;
  
                    /* Unresolved local var: char * cp_str@[???] */
  pcVar1 = (char *)setlocale(2,(char *)0x0);
  iVar2 = strchr(pcVar1,0x2e);
  uVar3 = 0;
  if (iVar2 != 0) {
    uVar3 = atoi((char *)(iVar2 + 1));
  }
  return uVar3;
}



// --- Function: init_codepage_func @ 0040fc10 ---

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

uint init_codepage_func(void)

{
  HMODULE hModule;
  code *pcVar1;
  uint uVar2;
  
                    /* Unresolved local var: HMODULE msvcrt@[???]
                       Unresolved local var: _func_uint * func@[???] */
  hModule = GetModuleHandleW(L"msvcrt.dll");
  if (hModule != (HMODULE)0x0) {
    pcVar1 = GetProcAddress(hModule,"___lc_codepage_func");
    if (pcVar1 == (_func_uint *)0x0) {
      msvcrt__lc_codepage = (uint *)GetProcAddress(hModule,"__lc_codepage");
      if ((FARPROC)msvcrt__lc_codepage == (FARPROC)0x0) goto LAB_0040fc58;
      pcVar1 = msvcrt___lc_codepage_func;
    }
    _imp_____lc_codepage_func = pcVar1;
    uVar2 = (*pcVar1)();
    return uVar2;
  }
LAB_0040fc58:
  _imp_____lc_codepage_func = setlocale_codepage_hack;
  uVar2 = setlocale_codepage_hack();
  return uVar2;
}



// --- Function: ___mb_cur_max_func @ 0040fca0 ---

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int ___mb_cur_max_func(void)

{
  return *(int *)__mb_cur_max_exref;
}



// --- Function: atoi @ 0040fcb0 ---

/* atoi */

void __cdecl atoi(char *param_1)

{
                    /* WARNING: Could not recover jumptable at 0x0040fcb0. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  atoi(param_1);
  return;
}



// --- Function: setlocale @ 0040fcb8 ---

/* setlocale */

void __cdecl setlocale(int param_1,char *param_2)

{
                    /* WARNING: Could not recover jumptable at 0x0040fcb8. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  setlocale(param_1,param_2);
  return;
}



// --- Function: strchr @ 0040fcc0 ---

/* strchr */

void __cdecl strchr(char *param_1,int param_2)

{
                    /* WARNING: Could not recover jumptable at 0x0040fcc0. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  strchr(param_1,param_2);
  return;
}



// --- Function: ___divdi3 @ 0040fcd0 ---

undefined8 __cdecl ___divdi3(uint param_1,uint param_2,uint param_3,uint param_4)

{
  ulonglong uVar1;
  ulonglong uVar2;
  ulonglong uVar3;
  longlong lVar4;
  byte bVar5;
  int iVar6;
  byte bVar7;
  uint uVar8;
  uint uVar9;
  bool bVar10;
  undefined4 local_2c;
  undefined4 local_24;
  
  local_24 = 0;
  local_2c = param_1;
  if ((int)param_2 < 0) {
    local_2c = -param_1;
    local_24 = 0xffffffff;
    param_2 = -(param_2 + (param_1 != 0));
  }
  if ((int)param_4 < 0) {
    bVar10 = param_3 != 0;
    param_3 = -param_3;
    local_24 = ~local_24;
    param_4 = -(param_4 + bVar10);
  }
  if (param_4 == 0) {
    if (param_2 < param_3) {
      uVar9 = 0;
      iVar6 = (int)(CONCAT44(param_2,local_2c) / (ulonglong)param_3);
    }
    else {
      if (param_3 == 0) {
        param_3 = 1 / 0;
      }
      uVar9 = param_2 / param_3;
      iVar6 = (int)(((ulonglong)param_2 % (ulonglong)param_3 << 0x20 | (ulonglong)local_2c) /
                   (ulonglong)param_3);
    }
  }
  else if (param_2 < param_4) {
    uVar9 = 0;
    iVar6 = 0;
  }
  else {
    uVar9 = 0x1f;
    if (param_4 != 0) {
      for (; param_4 >> uVar9 == 0; uVar9 = uVar9 - 1) {
      }
    }
    if ((uVar9 ^ 0x1f) == 0) {
      uVar9 = 0;
      if ((param_4 < param_2) || (iVar6 = 0, param_3 <= local_2c)) {
        iVar6 = 1;
      }
    }
    else {
      bVar5 = (byte)(uVar9 ^ 0x1f);
      bVar7 = 0x20 - bVar5;
      uVar1 = (ulonglong)(param_3 >> (bVar7 & 0x1f) | param_4 << (bVar5 & 0x1f));
      uVar2 = CONCAT44(param_2 >> (bVar7 & 0x1f),
                       param_2 << (bVar5 & 0x1f) | local_2c >> (bVar7 & 0x1f));
      uVar3 = uVar2 / uVar1;
      iVar6 = (int)uVar3;
      uVar9 = (uint)(uVar2 % uVar1);
      lVar4 = (uVar3 & 0xffffffff) * (ulonglong)(param_3 << (bVar5 & 0x1f));
      uVar8 = (uint)((ulonglong)lVar4 >> 0x20);
      if ((uVar9 < uVar8) || ((local_2c << (bVar5 & 0x1f) < (uint)lVar4 && (uVar9 == uVar8)))) {
        iVar6 = iVar6 + -1;
      }
      uVar9 = 0;
    }
  }
  if (local_24 != 0) {
    bVar10 = iVar6 != 0;
    iVar6 = -iVar6;
    uVar9 = -(uVar9 + bVar10);
  }
  return CONCAT44(uVar9,iVar6);
}



// --- Function: ___udivdi3 @ 0040fe10 ---

ulonglong __cdecl ___udivdi3(uint param_1,uint param_2,uint param_3,uint param_4)

{
  ulonglong uVar1;
  ulonglong uVar2;
  ulonglong uVar3;
  longlong lVar4;
  byte bVar5;
  uint uVar6;
  byte bVar7;
  uint uVar8;
  uint uVar9;
  
  if (param_4 != 0) {
    if (param_2 < param_4) {
      uVar6 = 0;
    }
    else {
      uVar6 = 0x1f;
      if (param_4 != 0) {
        for (; param_4 >> uVar6 == 0; uVar6 = uVar6 - 1) {
        }
      }
      if ((uVar6 ^ 0x1f) == 0) {
        if ((param_4 < param_2) || (uVar6 = 0, param_3 <= param_1)) {
          uVar6 = 1;
        }
      }
      else {
        bVar5 = (byte)(uVar6 ^ 0x1f);
        bVar7 = 0x20 - bVar5;
        uVar1 = (ulonglong)(param_3 >> (bVar7 & 0x1f) | param_4 << (bVar5 & 0x1f));
        uVar2 = CONCAT44(param_2 >> (bVar7 & 0x1f),
                         param_1 >> (bVar7 & 0x1f) | param_2 << (bVar5 & 0x1f));
        uVar3 = uVar2 / uVar1;
        uVar6 = (uint)uVar3;
        uVar8 = (uint)(uVar2 % uVar1);
        lVar4 = (uVar3 & 0xffffffff) * (ulonglong)(param_3 << (bVar5 & 0x1f));
        uVar9 = (uint)((ulonglong)lVar4 >> 0x20);
        if ((uVar8 < uVar9) || ((param_1 << (bVar5 & 0x1f) < (uint)lVar4 && (uVar8 == uVar9)))) {
          uVar6 = uVar6 - 1;
        }
      }
    }
    return (ulonglong)uVar6;
  }
  if (param_3 <= param_2) {
    if (param_3 == 0) {
      param_3 = 1 / 0;
    }
    return CONCAT44(param_2 / param_3,
                    (int)(((ulonglong)param_2 % (ulonglong)param_3 << 0x20 | (ulonglong)param_1) /
                         (ulonglong)param_3));
  }
  return CONCAT44(param_2,param_1) / (ulonglong)param_3 & 0xffffffff;
}



// --- Function: register_frame_ctor @ 0040ff30 ---

/* register_frame_ctor */

void __cdecl register_frame_ctor(void)

{
  HMODULE hModule;
  FARPROC pFVar1;
  
  hModule = GetModuleHandleA("libgcc_s_dw2-1.dll");
  if (hModule == (HMODULE)0x0) {
    _deregister_frame_fn = (FARPROC)0x0;
    pFVar1 = (FARPROC)0x0;
  }
  else {
    _hmod_libgcc = LoadLibraryA("libgcc_s_dw2-1.dll");
    pFVar1 = GetProcAddress(hModule,"__register_frame_info");
    _deregister_frame_fn = GetProcAddress(hModule,"__deregister_frame_info");
  }
  if (pFVar1 != (FARPROC)0x0) {
    (*pFVar1)(&___EH_FRAME_BEGIN__,&_obj);
  }
  atexit(___gcc_deregister_frame);
  return;
}



