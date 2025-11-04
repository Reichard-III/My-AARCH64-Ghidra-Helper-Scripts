Helper scripts I made to help speed up reverse engineering tasks

ReplaceWithNOP : replaces the selected instruction with NOP, created by Packt, modified by me to work with AARCH64

SetJumpTableReferencesForSwitchOverride : Used to fix broken jump tables in AARCH64v8. Locates the jump data and writes jump references from the BR (branch register) instruction to the jump destination addresses.
I made this for assembly compiled for FE3H so I don't know if there are other standard switch jump table compilation implementations this wouldn't work on. Only works on static jump tables, not vtable stuff.
I tried to make it extensible but this is futile since I have never seen any other jump table implementation to reference, so it only works for jump table with Signed_4Byte address offsets.

CreateEnumFromFile : Used to import an enum in a .txt file that is copy pasted from a 010 editor .bt into a ghidra enum. No support for anything else at the moment.
