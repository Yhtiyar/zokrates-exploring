const { initialize } = require("zokrates-js");
initialize()
  .then((zokratesProvider) => {
    const source =
      "def main(private field a, field b) ->field { assert(a == b*b); return 5;}";

    // compilation
    const artifacts = zokratesProvider.compile(source);
    // run setup
    const keypair = zokratesProvider.setup(artifacts.program);

    // computation
    const { witness, output } = zokratesProvider.computeWitness(artifacts, [
      "4",
      "2",
    ]);
    console.log(output);

    // generate proof
    const proof = zokratesProvider.generateProof(
      artifacts.program,
      witness,
      keypair.pk
    );

    //verify off-chain
    const isVerified = zokratesProvider.verify(keypair.vk, proof);
    console.log(isVerified);
  })
  .catch((err) => {
    console.log(err);
  });
