# DowngradeElf.Net

DowngradeElf.Net merge downgrade_elf & Downgrade-ELF-Patched and rewrite in C# with .Net Framework, elf downgrader python script made by flatz.

Usage: downgradeElf input [output] [Options]

     input  <old file>(required)
     output <new file, add "_new" to the end of the input filename when the output is not specified>
    
    Options:
     --sdk-version arg                  <wanted sdk version, leave 0(empty) for no patching
     05.050.001: usually used when converting sdk version>, default:0
     
     --patch-memhole arg                <patch memhole options:
     0: don't patch,
     1: extend the memory size of the segment to fill the memhole,
     2: move the segments after the memhole backwards>, default:1
     
     --patch-memhole-references arg     <patch memhole references options(this option is used when patch-memhole is 2):
     0: don't patch memory hole segments bytes
     1: patch memory hole segments bytes
     2: patch memory hole segments bytes that the bits from their end up to the replacement value bytes amount aren't 0
     3: patch memory hole segments bytes with addresses that aren't a multiply of 8>, default:1
    
     --dry-run                          <if inserted then nothing will be written to the output file>
     --overwrite                        <overwrite input file when the output path is not specified>
     --not-patch-program-headers        <not patch program headers>
     --not-patch-dynamic-section        <not patch dynamic section when patch-memhole is 2>
     --not-patch-relocation-section     <not patch relocation section when patch-memhole is 2>
     --not-patch-symbol-table           <not patch symbol table when patch-memhole is 2>
     --not-patch-elf-header             <not patch elf header>
     -v, --verbose                      <detailed printing>
 
 
 ## Reference  
 
 [flatz/downgrade_elf](https://twitter.com/flat_z/status/1284499782946390019)  
 [xSpecialFoodx/Downgrade-ELF-Patched](https://github.com/xSpecialFoodx/Downgrade-ELF-Patched)  
 [PS4 Backporting Instructions to Play 6.72 Games on 5.05 Firmware](https://www.psxhax.com/threads/ps4-backporting-instructions-to-play-6-72-games-on-5-05-firmware.7565/)  
 [PS4 Downgrade ELF Patched, SelfUtil Patched & Segments Fixer Updates](https://www.psxhax.com/threads/ps4-downgrade-elf-patched-selfutil-patched-segments-fixer-updates.9049/)  
 