// --- Function: FUN_18011a7b0 @ 18011a7b0 ---

/* WARNING: Control flow encountered bad instruction data */

void FUN_18011a7b0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



// --- Function: FUN_18017c01c @ 18017c01c ---

/* WARNING: Control flow encountered bad instruction data */

void FUN_18017c01c(undefined1 param_1)

{
  longlong unaff_RBP;
  longlong unaff_RSI;
  byte in_CF;
  
  *(int *)(unaff_RSI + -0x7b644e33) = *(int *)(unaff_RSI + -0x7b644e33) + 0x2b + (uint)in_CF;
  out(99,param_1);
  *(char *)(unaff_RBP + -0x425b910e) = *(char *)(unaff_RBP + -0x425b910e) + '\x01';
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



// --- Function: entry @ 1801b3190 ---

undefined8 entry(undefined8 param_1,char param_2)

{
  longlong lVar1;
  ushort uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 *puVar5;
  uint3 uVar6;
  undefined1 **ppuVar7;
  byte bVar8;
  char cVar9;
  uint uVar10;
  uint uVar11;
  BOOL BVar12;
  ulonglong uVar13;
  HMODULE hModule;
  FARPROC pFVar14;
  undefined4 extraout_var;
  undefined8 uVar15;
  uint uVar16;
  uint *puVar17;
  int iVar18;
  uint uVar19;
  int iVar20;
  undefined1 *puVar21;
  longlong lVar22;
  undefined8 *puVar23;
  ulonglong *puVar24;
  undefined1 *puVar25;
  undefined1 *puVar26;
  int iVar27;
  uint uVar28;
  int iVar29;
  byte *pbVar30;
  byte *pbVar31;
  uint *puVar32;
  uint *puVar33;
  uint *puVar34;
  uint uVar35;
  ushort *puVar36;
  ushort *puVar37;
  uint uVar38;
  undefined8 unaff_R12;
  byte *pbVar39;
  undefined8 unaff_R13;
  undefined8 unaff_R14;
  uint uVar40;
  undefined8 unaff_R15;
  undefined1 auStack_ec8 [3560];
  uint local_e0 [5];
  uint local_cc [3];
  longlong local_c0;
  uint local_b4;
  longlong local_b0 [2];
  int local_a0 [2];
  longlong alStack_98 [9];
  undefined1 *puStack_50;
  
  bVar8 = DAT_180118001;
  if (param_2 != '\x01') goto LAB_1801b3dc0;
  _tls_index = 0xd048f7c6;
  puStack_50 = &DAT_180118002;
  uVar13 = CONCAT71(0x1b11,DAT_180118000) & 0xffffffffffffff07;
  puVar21 = (undefined1 *)
            ((ulonglong)(auStack_ec8 + (-0x300L << (DAT_180118000 >> 3)) * 2) & 0xffffffffffffffc0);
  ppuVar7 = &puStack_50;
  do {
    puVar25 = (undefined1 *)ppuVar7;
    *(undefined8 *)(puVar25 + -8) = 0;
    ppuVar7 = (undefined1 **)(puVar25 + -8);
  } while (puVar25 + -8 != puVar21);
  *(undefined1 **)(puVar25 + -0x10) = puVar21;
  puVar21[10] = (char)uVar13;
  puVar21[9] = bVar8 >> 4;
  uVar13 = CONCAT71((int7)(uVar13 >> 8),bVar8) & 0xffffffffffffff0f;
  puVar21[8] = (byte)uVar13;
  *(ulonglong *)(puVar25 + -0x18) = uVar13;
  *(undefined8 *)(puVar25 + -0x20) = unaff_R15;
  uVar40 = 0;
  *(undefined8 *)(puVar25 + -0x28) = unaff_R14;
  uVar35 = 1;
  *(undefined8 *)(puVar25 + -0x30) = unaff_R13;
  uVar19 = 0;
  *(undefined8 *)(puVar25 + -0x38) = unaff_R12;
  *(undefined1 **)(puVar25 + -0x40) = &stack0xffffffffffffffb8;
  *(undefined1 **)(puVar25 + -0x48) = puVar21;
  *(undefined1 **)(puVar25 + -0x58) = puVar21 + 4;
  *(undefined1 **)(puVar25 + -0x70) = puVar21 + 0xc;
  *(undefined1 **)(puVar25 + -0x50) = &DAT_180118002;
  *(undefined1 **)(puVar25 + -0x60) = &DAT_180001000;
  *(undefined4 *)(puVar25 + -100) = 0x1b11bb;
  puVar5 = *(undefined4 **)(puVar25 + -0x10);
  *(int *)(puVar25 + -0x74) = (1 << (puVar21[10] & 0x1f)) + -1;
  *(int *)(puVar25 + -0x78) = (1 << (puVar21[9] & 0x1f)) + -1;
  bVar8 = puVar21[8];
  **(undefined4 **)(puVar25 + -0x58) = 0;
  *(undefined4 *)(puVar25 + -0x80) = 0;
  *(undefined4 *)(puVar25 + -0x84) = 1;
  *(undefined4 *)(puVar25 + -0x88) = 1;
  *(undefined4 *)(puVar25 + -0x8c) = 1;
  *puVar5 = 0;
  *(uint *)(puVar25 + -0x7c) = (uint)bVar8;
  cVar9 = puVar21[9];
  for (uVar16 = 0; uVar16 < (0x300 << (cVar9 + bVar8 & 0x1f)) + 0x736U; uVar16 = uVar16 + 1) {
    *(undefined2 *)(*(longlong *)(puVar25 + -0x70) + (ulonglong)uVar16 * 2) = 0x400;
  }
  pbVar31 = *(byte **)(puVar25 + -0x50);
  uVar38 = 0;
  uVar16 = 0xffffffff;
  iVar18 = 0;
  pbVar39 = pbVar31 + 0x9b17f;
  do {
    if (pbVar31 == pbVar39) goto LAB_1801b3c2c;
    bVar8 = *pbVar31;
    iVar18 = iVar18 + 1;
    pbVar31 = pbVar31 + 1;
    uVar38 = uVar38 << 8 | (uint)bVar8;
  } while (iVar18 < 5);
  if (*(int *)(puVar25 + -100) != 0) {
LAB_1801b333c:
    lVar22 = (longlong)*(int *)(puVar25 + -0x80);
    *(uint *)(puVar25 + -0x90) = *(uint *)(puVar25 + -0x74) & uVar40;
    iVar18 = *(int *)(puVar25 + -0x90);
    puVar37 = (ushort *)(*(longlong *)(puVar25 + -0x70) + (lVar22 * 0x10 + (longlong)iVar18) * 2);
    if (uVar16 < 0x1000000) {
      if (pbVar31 == pbVar39) goto LAB_1801b3c2c;
      bVar8 = *pbVar31;
      uVar16 = uVar16 << 8;
      pbVar31 = pbVar31 + 1;
      uVar38 = uVar38 << 8 | (uint)bVar8;
    }
    uVar2 = *puVar37;
    uVar10 = (uVar16 >> 0xb) * (uint)uVar2;
    if (uVar38 < uVar10) {
      lVar22 = *(longlong *)(puVar25 + -0x70);
      bVar8 = puVar25[-0x7c];
      uVar28 = 1;
      *puVar37 = uVar2 + (short)((int)(0x800 - (uint)uVar2) >> 5);
      lVar22 = lVar22 + 0xe6c +
               (ulonglong)
               ((((*(uint *)(puVar25 + -0x78) & uVar40) << (bVar8 & 0x1f)) +
                ((int)(uVar19 & 0xff) >> (8U - (char)*(undefined4 *)(puVar25 + -0x7c) & 0x1f))) *
               0x300) * 2;
      uVar16 = uVar10;
      if (*(int *)(puVar25 + -0x80) < 7) goto LAB_1801b34ae;
      uVar10 = (uint)*(byte *)(*(longlong *)(puVar25 + -0x60) + (ulonglong)(uVar40 - uVar35));
      do {
        uVar10 = uVar10 * 2;
        uVar19 = uVar10 & 0x100;
        lVar1 = lVar22 + (longlong)(int)uVar19 * 2 + (longlong)(int)uVar28 * 2;
        if (uVar16 < 0x1000000) {
          if (pbVar31 == pbVar39) goto LAB_1801b3c2c;
          bVar8 = *pbVar31;
          uVar16 = uVar16 << 8;
          pbVar31 = pbVar31 + 1;
          uVar38 = uVar38 << 8 | (uint)bVar8;
        }
        uVar2 = *(ushort *)(lVar1 + 0x200);
        uVar11 = (uVar16 >> 0xb) * (uint)uVar2;
        if (uVar38 < uVar11) {
          uVar28 = uVar28 * 2;
          *(ushort *)(lVar1 + 0x200) = uVar2 + (short)((int)(0x800 - (uint)uVar2) >> 5);
          uVar16 = uVar11;
          if (uVar19 != 0) goto LAB_1801b34a6;
        }
        else {
          uVar16 = uVar16 - uVar11;
          uVar38 = uVar38 - uVar11;
          uVar28 = uVar28 * 2 + 1;
          *(ushort *)(lVar1 + 0x200) = uVar2 - (uVar2 >> 5);
          if (uVar19 == 0) goto LAB_1801b34a6;
        }
        uVar19 = uVar28;
      } while ((int)uVar28 < 0x100);
      goto LAB_1801b351e;
    }
    uVar16 = uVar16 - uVar10;
    uVar38 = uVar38 - uVar10;
    lVar1 = *(longlong *)(puVar25 + -0x70);
    *puVar37 = uVar2 - (uVar2 >> 5);
    lVar1 = lVar1 + lVar22 * 2;
    if (uVar16 < 0x1000000) {
      if (pbVar31 == pbVar39) goto LAB_1801b3c2c;
      bVar8 = *pbVar31;
      uVar16 = uVar16 * 0x100;
      pbVar31 = pbVar31 + 1;
      uVar38 = uVar38 * 0x100 | (uint)bVar8;
    }
    uVar2 = *(ushort *)(lVar1 + 0x180);
    uVar19 = (uVar16 >> 0xb) * (uint)uVar2;
    if (uVar19 <= uVar38) {
      uVar16 = uVar16 - uVar19;
      uVar38 = uVar38 - uVar19;
      *(ushort *)(lVar1 + 0x180) = uVar2 - (uVar2 >> 5);
      if (uVar16 < 0x1000000) {
        if (pbVar31 == pbVar39) goto LAB_1801b3c2c;
        bVar8 = *pbVar31;
        uVar16 = uVar16 * 0x100;
        pbVar31 = pbVar31 + 1;
        uVar38 = uVar38 * 0x100 | (uint)bVar8;
      }
      uVar2 = *(ushort *)(lVar1 + 0x198);
      uVar19 = (uVar16 >> 0xb) * (uint)uVar2;
      if (uVar38 < uVar19) {
        *(ushort *)(lVar1 + 0x198) = uVar2 + (short)((int)(0x800 - (uint)uVar2) >> 5);
        lVar22 = *(longlong *)(puVar25 + -0x70) + lVar22 * 0x20 + (longlong)iVar18 * 2;
        if (uVar19 < 0x1000000) {
          if (pbVar31 == pbVar39) goto LAB_1801b3c2c;
          bVar8 = *pbVar31;
          uVar19 = uVar19 * 0x100;
          pbVar31 = pbVar31 + 1;
          uVar38 = uVar38 << 8 | (uint)bVar8;
        }
        uVar2 = *(ushort *)(lVar22 + 0x1e0);
        uVar16 = (uVar19 >> 0xb) * (uint)uVar2;
        if (uVar16 <= uVar38) {
          uVar19 = uVar19 - uVar16;
          uVar38 = uVar38 - uVar16;
          *(ushort *)(lVar22 + 0x1e0) = uVar2 - (uVar2 >> 5);
          uVar16 = uVar35;
          goto LAB_1801b383e;
        }
        *(ushort *)(lVar22 + 0x1e0) = uVar2 + (short)((int)(0x800 - (uint)uVar2) >> 5);
        if (uVar40 != 0) {
          *(uint *)(puVar25 + -0x80) =
               (6 < *(int *)(puVar25 + -0x80)) + 9 + (uint)(6 < *(int *)(puVar25 + -0x80));
          bVar8 = *(byte *)(*(longlong *)(puVar25 + -0x60) + (ulonglong)(uVar40 - uVar35));
          uVar19 = (uint)bVar8;
          uVar13 = (ulonglong)uVar40;
          uVar40 = uVar40 + 1;
          *(byte *)(*(longlong *)(puVar25 + -0x60) + uVar13) = bVar8;
          goto LAB_1801b3be8;
        }
        goto LAB_1801b3c2c;
      }
      uVar16 = uVar16 - uVar19;
      uVar38 = uVar38 - uVar19;
      *(ushort *)(lVar1 + 0x198) = uVar2 - (uVar2 >> 5);
      if (uVar16 < 0x1000000) {
        if (pbVar31 == pbVar39) goto LAB_1801b3c2c;
        bVar8 = *pbVar31;
        uVar16 = uVar16 * 0x100;
        pbVar31 = pbVar31 + 1;
        uVar38 = uVar38 * 0x100 | (uint)bVar8;
      }
      uVar2 = *(ushort *)(lVar1 + 0x1b0);
      uVar19 = (uVar16 >> 0xb) * (uint)uVar2;
      if (uVar38 < uVar19) {
        *(ushort *)(lVar1 + 0x1b0) = uVar2 + (short)((int)(0x800 - (uint)uVar2) >> 5);
        uVar16 = *(uint *)(puVar25 + -0x84);
      }
      else {
        uVar16 = uVar16 - uVar19;
        uVar38 = uVar38 - uVar19;
        *(ushort *)(lVar1 + 0x1b0) = uVar2 - (uVar2 >> 5);
        if (uVar16 < 0x1000000) {
          if (pbVar31 == pbVar39) goto LAB_1801b3c2c;
          bVar8 = *pbVar31;
          uVar16 = uVar16 * 0x100;
          pbVar31 = pbVar31 + 1;
          uVar38 = uVar38 * 0x100 | (uint)bVar8;
        }
        uVar2 = *(ushort *)(lVar1 + 0x1c8);
        uVar10 = (uVar16 >> 0xb) * (uint)uVar2;
        if (uVar38 < uVar10) {
          *(ushort *)(lVar1 + 0x1c8) = uVar2 + (short)((int)(0x800 - (uint)uVar2) >> 5);
          uVar16 = *(uint *)(puVar25 + -0x88);
          uVar19 = uVar10;
        }
        else {
          uVar19 = uVar16 - uVar10;
          uVar38 = uVar38 - uVar10;
          uVar16 = *(uint *)(puVar25 + -0x8c);
          *(ushort *)(lVar1 + 0x1c8) = uVar2 - (uVar2 >> 5);
          *(undefined4 *)(puVar25 + -0x8c) = *(undefined4 *)(puVar25 + -0x88);
        }
        *(undefined4 *)(puVar25 + -0x88) = *(undefined4 *)(puVar25 + -0x84);
      }
      *(uint *)(puVar25 + -0x84) = uVar35;
LAB_1801b383e:
      puVar37 = (ushort *)(*(longlong *)(puVar25 + -0x70) + 0xa68);
      *(uint *)(puVar25 + -0x80) = (uint)(6 < *(int *)(puVar25 + -0x80)) * 3 + 8;
      uVar35 = uVar16;
      goto LAB_1801b385c;
    }
    lVar22 = *(longlong *)(puVar25 + -0x70);
    uVar3 = *(undefined4 *)(puVar25 + -0x84);
    *(uint *)(puVar25 + -0x84) = uVar35;
    uVar4 = *(undefined4 *)(puVar25 + -0x88);
    *(undefined4 *)(puVar25 + -0x88) = uVar3;
    *(ushort *)(lVar1 + 0x180) = uVar2 + (short)((int)(0x800 - (uint)uVar2) >> 5);
    *(undefined4 *)(puVar25 + -0x8c) = uVar4;
    puVar37 = (ushort *)(lVar22 + 0x664);
    *(uint *)(puVar25 + -0x80) = (uint)(6 < *(int *)(puVar25 + -0x80)) * 3;
LAB_1801b385c:
    if (uVar19 < 0x1000000) {
      if (pbVar31 == pbVar39) goto LAB_1801b3c2c;
      bVar8 = *pbVar31;
      uVar19 = uVar19 << 8;
      pbVar31 = pbVar31 + 1;
      uVar38 = uVar38 << 8 | (uint)bVar8;
    }
    uVar2 = *puVar37;
    uVar16 = (uVar19 >> 0xb) * (uint)uVar2;
    if (uVar38 < uVar16) {
      iVar18 = 0;
      *puVar37 = uVar2 + (short)((int)(0x800 - (uint)uVar2) >> 5);
      lVar22 = (longlong)*(int *)(puVar25 + -0x90) * 8 + 2;
LAB_1801b3931:
      puVar36 = puVar37 + lVar22;
      iVar29 = 3;
    }
    else {
      uVar19 = uVar19 - uVar16;
      uVar38 = uVar38 - uVar16;
      *puVar37 = uVar2 - (uVar2 >> 5);
      if (uVar19 < 0x1000000) {
        if (pbVar31 == pbVar39) goto LAB_1801b3c2c;
        bVar8 = *pbVar31;
        uVar19 = uVar19 * 0x100;
        pbVar31 = pbVar31 + 1;
        uVar38 = uVar38 * 0x100 | (uint)bVar8;
      }
      uVar2 = puVar37[1];
      uVar10 = (uVar19 >> 0xb) * (uint)uVar2;
      if (uVar38 < uVar10) {
        iVar18 = 8;
        puVar37[1] = uVar2 + (short)((int)(0x800 - (uint)uVar2) >> 5);
        lVar22 = (longlong)*(int *)(puVar25 + -0x90) * 8 + 0x82;
        uVar16 = uVar10;
        goto LAB_1801b3931;
      }
      uVar16 = uVar19 - uVar10;
      uVar38 = uVar38 - uVar10;
      puVar36 = puVar37 + 0x102;
      iVar18 = 0x10;
      puVar37[1] = uVar2 - (uVar2 >> 5);
      iVar29 = 8;
    }
    iVar27 = 1;
    iVar20 = iVar29;
    do {
      puVar37 = puVar36 + iVar27;
      if (uVar16 < 0x1000000) {
        if (pbVar31 == pbVar39) goto LAB_1801b3c2c;
        bVar8 = *pbVar31;
        uVar16 = uVar16 << 8;
        pbVar31 = pbVar31 + 1;
        uVar38 = uVar38 << 8 | (uint)bVar8;
      }
      uVar2 = *puVar37;
      uVar19 = (uVar16 >> 0xb) * (uint)uVar2;
      if (uVar38 < uVar19) {
        iVar27 = iVar27 * 2;
        *puVar37 = uVar2 + (short)((int)(0x800 - (uint)uVar2) >> 5);
        uVar16 = uVar19;
      }
      else {
        uVar16 = uVar16 - uVar19;
        uVar38 = uVar38 - uVar19;
        iVar27 = iVar27 * 2 + 1;
        *puVar37 = uVar2 - (uVar2 >> 5);
      }
      iVar20 = iVar20 + -1;
    } while (iVar20 != 0);
    iVar18 = (iVar27 - (1 << (sbyte)iVar29)) + iVar18;
    if (*(int *)(puVar25 + -0x80) < 4) {
      *(int *)(puVar25 + -0x80) = *(int *)(puVar25 + -0x80) + 7;
      iVar29 = 3;
      if (iVar18 < 4) {
        iVar29 = iVar18;
      }
      lVar22 = *(longlong *)(puVar25 + -0x70);
      iVar27 = 1;
      iVar20 = 6;
      do {
        puVar37 = (ushort *)(lVar22 + 0x360 + (longlong)iVar29 * 0x80 + (longlong)iVar27 * 2);
        if (uVar16 < 0x1000000) {
          if (pbVar31 == pbVar39) goto LAB_1801b3c2c;
          bVar8 = *pbVar31;
          uVar16 = uVar16 << 8;
          pbVar31 = pbVar31 + 1;
          uVar38 = uVar38 << 8 | (uint)bVar8;
        }
        uVar2 = *puVar37;
        uVar19 = (uVar16 >> 0xb) * (uint)uVar2;
        if (uVar38 < uVar19) {
          iVar27 = iVar27 * 2;
          *puVar37 = uVar2 + (short)((int)(0x800 - (uint)uVar2) >> 5);
          uVar16 = uVar19;
        }
        else {
          uVar16 = uVar16 - uVar19;
          uVar38 = uVar38 - uVar19;
          iVar27 = iVar27 * 2 + 1;
          *puVar37 = uVar2 - (uVar2 >> 5);
        }
        iVar20 = iVar20 + -1;
      } while (iVar20 != 0);
      uVar35 = iVar27 - 0x40;
      if (3 < (int)uVar35) {
        uVar19 = uVar35 & 1 | 2;
        iVar29 = ((int)uVar35 >> 1) + -1;
        if ((int)uVar35 < 0xe) {
          lVar22 = (longlong)(int)uVar35;
          uVar35 = uVar19 << ((byte)iVar29 & 0x1f);
          lVar22 = *(longlong *)(puVar25 + -0x70) + (ulonglong)uVar35 * 2 + lVar22 * -2 + 0x55e;
        }
        else {
          iVar29 = ((int)uVar35 >> 1) + -5;
          do {
            if (uVar16 < 0x1000000) {
              if (pbVar31 == pbVar39) goto LAB_1801b3c2c;
              bVar8 = *pbVar31;
              uVar16 = uVar16 << 8;
              pbVar31 = pbVar31 + 1;
              uVar38 = uVar38 << 8 | (uint)bVar8;
            }
            uVar16 = uVar16 >> 1;
            uVar19 = uVar19 * 2;
            if (uVar16 <= uVar38) {
              uVar38 = uVar38 - uVar16;
              uVar19 = uVar19 | 1;
            }
            iVar29 = iVar29 + -1;
          } while (iVar29 != 0);
          uVar35 = uVar19 << 4;
          iVar29 = 4;
          lVar22 = *(longlong *)(puVar25 + -0x70) + 0x644;
        }
        uVar19 = 1;
        iVar27 = 1;
        do {
          puVar37 = (ushort *)(lVar22 + (longlong)iVar27 * 2);
          if (uVar16 < 0x1000000) {
            if (pbVar31 == pbVar39) goto LAB_1801b3c2c;
            bVar8 = *pbVar31;
            uVar16 = uVar16 << 8;
            pbVar31 = pbVar31 + 1;
            uVar38 = uVar38 << 8 | (uint)bVar8;
          }
          uVar2 = *puVar37;
          uVar10 = (uVar16 >> 0xb) * (uint)uVar2;
          if (uVar38 < uVar10) {
            iVar27 = iVar27 * 2;
            *puVar37 = uVar2 + (short)((int)(0x800 - (uint)uVar2) >> 5);
            uVar16 = uVar10;
          }
          else {
            uVar16 = uVar16 - uVar10;
            uVar38 = uVar38 - uVar10;
            iVar27 = iVar27 * 2 + 1;
            uVar35 = uVar35 | uVar19;
            *puVar37 = uVar2 - (uVar2 >> 5);
          }
          uVar19 = uVar19 * 2;
          iVar29 = iVar29 + -1;
        } while (iVar29 != 0);
      }
      uVar35 = uVar35 + 1;
      if (uVar35 == 0) goto LAB_1801b3bf3;
    }
    iVar18 = iVar18 + 2;
    if (uVar40 < uVar35) goto LAB_1801b3c2c;
    do {
      bVar8 = *(byte *)(*(longlong *)(puVar25 + -0x60) + (ulonglong)(uVar40 - uVar35));
      uVar19 = (uint)bVar8;
      uVar13 = (ulonglong)uVar40;
      uVar40 = uVar40 + 1;
      iVar18 = iVar18 + -1;
      *(byte *)(*(longlong *)(puVar25 + -0x60) + uVar13) = bVar8;
    } while (iVar18 != 0 && uVar40 < *(uint *)(puVar25 + -100));
    goto LAB_1801b3be8;
  }
LAB_1801b3c12:
  puVar32 = *(uint **)(puVar25 + -0x10);
  **(int **)(puVar25 + -0x58) = (int)pbVar31 - *(int *)(puVar25 + -0x50);
  *puVar32 = uVar40;
  goto LAB_1801b3c2c;
LAB_1801b34a6:
  uVar19 = uVar28;
  if ((int)uVar28 < 0x100) {
LAB_1801b34ae:
    puVar37 = (ushort *)(lVar22 + (longlong)(int)uVar28 * 2);
    if (uVar16 < 0x1000000) {
      if (pbVar31 == pbVar39) goto LAB_1801b3c2c;
      bVar8 = *pbVar31;
      uVar16 = uVar16 << 8;
      pbVar31 = pbVar31 + 1;
      uVar38 = uVar38 << 8 | (uint)bVar8;
    }
    uVar2 = *puVar37;
    uVar19 = (uVar16 >> 0xb) * (uint)uVar2;
    if (uVar38 < uVar19) {
      uVar28 = uVar28 * 2;
      *puVar37 = uVar2 + (short)((int)(0x800 - (uint)uVar2) >> 5);
      uVar16 = uVar19;
    }
    else {
      uVar38 = uVar38 - uVar19;
      uVar28 = uVar28 * 2 + 1;
      *puVar37 = uVar2 - (uVar2 >> 5);
      uVar16 = uVar16 - uVar19;
    }
    goto LAB_1801b34a6;
  }
LAB_1801b351e:
  uVar13 = (ulonglong)uVar40;
  uVar40 = uVar40 + 1;
  *(char *)(*(longlong *)(puVar25 + -0x60) + uVar13) = (char)uVar19;
  if (*(int *)(puVar25 + -0x80) < 4) {
    *(undefined4 *)(puVar25 + -0x80) = 0;
  }
  else {
    iVar18 = *(int *)(puVar25 + -0x80) + -3;
    if (9 < *(int *)(puVar25 + -0x80)) {
      iVar18 = *(int *)(puVar25 + -0x80) + -6;
    }
    *(int *)(puVar25 + -0x80) = iVar18;
  }
LAB_1801b3be8:
  if (*(uint *)(puVar25 + -100) <= uVar40) goto LAB_1801b3bf3;
  goto LAB_1801b333c;
LAB_1801b3bf3:
  if (0xffffff < uVar16) goto LAB_1801b3c12;
  if (pbVar31 != pbVar39) {
    pbVar31 = pbVar31 + 1;
    goto LAB_1801b3c12;
  }
LAB_1801b3c2c:
  uVar15 = *(undefined8 *)(puVar25 + -0x48);
  lVar22 = *(longlong *)(puVar25 + -0x40);
  lVar1 = *(longlong *)(lVar22 + 0x10);
  **(undefined4 **)(lVar22 + 0x18) = (int)*(undefined8 *)(lVar22 + 0x20);
  *(longlong *)(lVar22 + 0x20) = lVar1;
  *(undefined8 *)(lVar22 + 0x18) = uVar15;
  *(longlong *)(lVar22 + 0x10) = lVar1;
  pbVar31 = (byte *)(lVar1 + 0x1205fd);
  pbVar39 = *(byte **)(lVar22 + 0x10);
  *(byte **)(lVar22 + 0x10) = pbVar39;
  uVar15 = *(undefined8 *)(lVar22 + 0x10);
LAB_1801b3c8c:
  if (pbVar39 < pbVar31) {
    pbVar30 = pbVar39 + 1;
    bVar8 = *pbVar39;
    while( true ) {
      if ((byte)(bVar8 + 0x18) < 2) goto LAB_1801b3c79;
      if (pbVar31 <= pbVar30) break;
      *(byte **)(lVar22 + 0x10) = pbVar30;
      while( true ) {
        pbVar39 = *(byte **)(lVar22 + 0x10);
        pbVar30 = pbVar39 + 1;
        bVar8 = *pbVar39;
        if (((bVar8 < 0x80) || (0x8f < bVar8)) || (pbVar39[-1] != 0xf)) break;
LAB_1801b3c79:
        if (pbVar31 <= pbVar30) goto LAB_1801b3c94;
        *(byte **)(lVar22 + 0x10) = pbVar30;
        pbVar39 = pbVar30 + 4;
        uVar6 = (uint3)((uint)*(undefined4 *)pbVar30 >> 8);
        cVar9 = (char)*(undefined4 *)pbVar30 + -0x1b;
        if (cVar9 == '\0') {
          **(int **)(lVar22 + 0x10) =
               (((uint)(uVar6 >> 0x10) | uVar6 & 0xff00 | (uVar6 & 0xff) << 0x10 |
                CONCAT31(uVar6,cVar9) << 0x18) - (int)*(int **)(lVar22 + 0x10)) + (int)uVar15;
          goto LAB_1801b3c8c;
        }
      }
    }
  }
LAB_1801b3c94:
  lVar1 = *(longlong *)(lVar22 + 0x20);
  puVar32 = (uint *)(lVar1 + 0x1af000);
  while (uVar19 = *puVar32, uVar19 != 0) {
    puVar23 = (undefined8 *)((ulonglong)puVar32[1] + lVar1);
    puVar34 = puVar32 + 2;
    *(undefined8 *)(lVar22 + -8) = 0x1801b3cbf;
    hModule = LoadLibraryA((LPCSTR)((ulonglong)uVar19 + 0x1b4000 + lVar1));
    while( true ) {
      cVar9 = (char)*puVar34;
      puVar32 = (uint *)((longlong)puVar34 + 1);
      if (cVar9 == '\0') break;
      if (cVar9 < '\0') {
        puVar32 = (uint *)(ulonglong)*(ushort *)puVar32;
        puVar34 = (uint *)((longlong)puVar34 + 3);
      }
      else {
        puVar17 = puVar32;
        puVar33 = puVar32;
        do {
          puVar34 = puVar33;
          if (puVar17 == (uint *)0x0) break;
          puVar17 = (uint *)((longlong)puVar17 + -1);
          puVar34 = (uint *)((longlong)puVar33 + 1);
          uVar19 = *puVar33;
          puVar33 = puVar34;
        } while ((char)(cVar9 + -1) != (char)uVar19);
      }
      *(undefined8 *)(lVar22 + -8) = 0x1801b3ce9;
      pFVar14 = GetProcAddress(hModule,(LPCSTR)puVar32);
      if (pFVar14 == (FARPROC)0x0) {
        return 0;
      }
      *puVar23 = pFVar14;
      puVar23 = puVar23 + 1;
    }
  }
  puVar24 = (ulonglong *)(lVar1 + -4);
  puVar32 = puVar32 + 1;
  while( true ) {
    bVar8 = (byte)*puVar32;
    uVar13 = (ulonglong)bVar8;
    puVar34 = (uint *)((longlong)puVar32 + 1);
    if (bVar8 == 0) break;
    if (0xef < bVar8) {
      uVar2 = *(ushort *)puVar34;
      puVar34 = (uint *)((longlong)puVar32 + 3);
      uVar13 = (ulonglong)(CONCAT12(bVar8,uVar2) & 0xff0fffff);
      if ((CONCAT12(bVar8,uVar2) & 0xfffff) == 0) {
        uVar13 = (ulonglong)*puVar34;
        puVar34 = (uint *)((longlong)puVar32 + 7);
      }
    }
    puVar24 = (ulonglong *)((longlong)puVar24 + uVar13);
    uVar13 = *puVar24;
    *puVar24 = (uVar13 >> 0x38 | (uVar13 & 0xff000000000000) >> 0x28 |
                (uVar13 & 0xff0000000000) >> 0x18 | (uVar13 & 0xff00000000) >> 8 |
                (uVar13 & 0xff000000) << 8 | (uVar13 & 0xff0000) << 0x18 | (uVar13 & 0xff00) << 0x28
               | uVar13 << 0x38) + lVar1;
    puVar32 = puVar34;
  }
  *(undefined8 *)(lVar22 + 0x20) = 0;
  *(undefined8 *)(lVar22 + -8) = 0x1801b3d6f;
  VirtualProtect((LPVOID)(lVar1 + -0x1000),0x1000,4,(PDWORD)(lVar22 + 0x20));
  *(byte *)(lVar1 + -0xdc9) = *(byte *)(lVar1 + -0xdc9) & 0x7f;
  *(byte *)(lVar1 + -0xda1) = *(byte *)(lVar1 + -0xda1) & 0x7f;
  *(undefined8 *)(lVar22 + -8) = 0x1801b3d8d;
  BVar12 = VirtualProtect((LPVOID)(lVar1 + -0x1000),0x1000,(DWORD)*(undefined8 *)(lVar22 + 0x20),
                          (PDWORD)(lVar22 + 0x20));
  tls_callback_0 = (code)0xfc;
  *(undefined8 *)(lVar22 + 0x20) = 1;
  *(ulonglong *)(lVar22 + 0x20) = CONCAT44(extraout_var,BVar12);
  *(undefined8 *)(lVar22 + 0x18) = 0x1801b3dab;
  tls_callback_0();
  puVar21 = (undefined1 *)(lVar22 + 0x48);
  do {
    puVar26 = puVar21 + -8;
    *(undefined8 *)(puVar21 + -8) = 0;
    puVar21 = puVar21 + -8;
  } while (puVar26 != (undefined1 *)(lVar22 + -0x38));
LAB_1801b3dc0:
  uVar15 = FUN_18011a7b0();
  return uVar15;
}



// --- Function: tls_callback_0 @ 1801b3dd4 ---

void tls_callback_0(void)

{
  return;
}



