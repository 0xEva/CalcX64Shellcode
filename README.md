# CalcX64Shellcode
Baby's First Shellcode in C

## Special Thanks
1. **hasherezade**: Her comprehensive guide, ["From a C project, through assembly, to shellcode"](https://samples.vx-underground.org/root/Papers/Windows/Analysis%20and%20Internals/2020-10-11%20-%20From%20a%20C%20project%20through%20assembly%20to%20shellcode.pdf), is instrumental to this project.

2. **Capt. Meelo**: ["Making NtCreateUserProcess Work"](https://captmeelo.com/redteam/maldev/2022/05/10/ntcreateuserprocess.html)

## Improvment
1. We can eliminate our depency on RtlCreateProcessParametersEx() by either manually create it on stack or paritaly copy from PEB->ProcessParameters.
2. Implement function lookup by hash. This should both increase stealth and reduce payload size.
