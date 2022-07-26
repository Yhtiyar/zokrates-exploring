#!/bin/sh
# It is the first time I write a shell script
artifacts_dir="$(pwd)/artifacts"
circuit_name="$(echo "$1" | cut -f 1 -d '.')"
echo "Circuit name: $circuit_name"
[ ! -d $artifacts_dir ] && mkdir $artifacts_dir && echo "Created artifacts directory: $artifacts_dir" 

echo "Compiling circuit..."
zokrates compile -i $1 \
                -o "$artifacts_dir/$circuit_name.out" \
                -r "$artifacts_dir/$circuit_name.out.r1cs" \
                -s "$artifacts_dir/$circuit_name.abi.json" 

exit_code=$?
if [ $exit_code -eq 0 ] 
then
    echo "Compilation succeed"
else
    echo "Compilation failed"
    exit 1
fi


echo "Generating keypair..."
zokrates setup  -i "$artifacts_dir/$circuit_name.out" \
                -p "$artifacts_dir/$circuit_name.proving.key" \
                -v  "$artifacts_dir/$circuit_name.verification.key"


exit_code=$?
if [ $exit_code -eq 0 ] 
then
    echo "Generation keypair succeed"
else
    echo "Generation keypair failed"
    exit 1
fi

echo "Generating solidity verifier..."
zokrates export-verifier -i "$artifacts_dir/$circuit_name.verification.key" \
                         -o "$artifacts_dir/$circuit_name.Verifier.sol"


exit_code=$?
if [ $exit_code -eq 0 ] 
then
    echo "Generation of solidity verifier succeed"
else
    echo "Generation of solidity verifier failed"
    exit 1
fi