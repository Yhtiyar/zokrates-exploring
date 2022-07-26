// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;
library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }


    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2,
            G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}

contract Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x08e5c66e8e1a24cadc380bb1ece233ac407150a413a6104f71e60a90ea1e675b), uint256(0x009b3682af52ab0fcdb68b22c499deef18ef683646727ace5f9d7ae734dc3b8a));
        vk.beta = Pairing.G2Point([uint256(0x01c8de1c3d3bd8788b35acd0a0b71bcc5225e4004ac8c33d5387ce1f401df05a), uint256(0x1aa0b1ebac5cc16b9da9efb2d6ed5f9cc547848df0dbca34a2f990bee265f9a5)], [uint256(0x1140ca5b6083dbeda500fefae9a94e96a8078531ed5622bc7d1e44c2fe5f6848), uint256(0x0182a890c89642de5c96b4e55d929a949350892d7811245d11292b03051642fa)]);
        vk.gamma = Pairing.G2Point([uint256(0x18a92236e062d8e40c6ef4438536551eb38e14ae3115b89d6fe9ed2f8de5ee13), uint256(0x19e61e0917d2ad0aa950538492f5477fa5d72c417af1140284c2ee96de17a0a7)], [uint256(0x0af34e3087a1accdb4dfa812ceb270c6a5e119141568febd424e2e5e172e7229), uint256(0x2ee9812056b4049405c0b9fb435281a73fa01b65d86e37c88b468b2f3b869494)]);
        vk.delta = Pairing.G2Point([uint256(0x2786770ee1bc68be68090caef0bdd34d163bedd17dd6bf720d14aeefafc38baf), uint256(0x127e40716a91023c726a9c597df9997f2a0b888555f40f5643eee2ebb544dfaa)], [uint256(0x1d501a35911738f34f625c9988c1f8975639ad22ea022af61da008c7b97573d1), uint256(0x0ab2ce328967a01878f75ba796500e903f6c5adc9e1071afa96ed4f8b276f8f3)]);
        vk.gamma_abc = new Pairing.G1Point[](9);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x09793fbd7e76ff011eb005402c539ccfbbe255f3012a0b546214dd7cb6d308ae), uint256(0x29441f59364a793d7fe4561eb0a73fcf4d2af320755fec789a87821ec5f8b55a));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x1803f2e799f577f1cb3267cb66a063dc98c060cd1fbc7fe49a9e303eb7ef0627), uint256(0x1c7a6dea6bd96f0414d5e0f43084dc1ef5de0365ebe93e2fd34d9f971ce2de32));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x08d658c7a5bb4a61dda339cc9d57bbae7a113dd78c4b7f228dfe574233dbf228), uint256(0x19d7cd760a51d5b83296d8eccc4e8772b020a09d1eeb0374d05ada2c62b74238));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x13066737a2bd931b8bf1f3c3beed91ca13a2f711a4d0fda2f423f32f575f4b93), uint256(0x27c6113e04689f0b054b1b30e96276eb83bc2083e5257ce57e4200ee9bd6e7ba));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x2113fe8743c53d7d2c2db37019e92cbd36d38e09687e34a97f5ddfe4da2f2adb), uint256(0x04aeebb4b86f22dd23efbe8ae4cee50bba8cbe9602b15b5ab2c9bf1692f458c4));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x106d74c61b7730570d36e970f8e5bc9d52a51a68175354bf0d81272df68f8826), uint256(0x0ab495cc69d015cb5845b96eddba0591c8e16188d2949b8cb02f38ae87e66d35));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x2fe31a8ffe861c006ae2027720f2681f50a33bb1e661436c3d5739ce55dedd3b), uint256(0x1c515c093d6e8124c8547a5907d0fd1fbd7f5e5baaac12226be3fad72a71f334));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x221764441b6b300e836ed06482710a0465dc63e6532517a4cac58f1ed5625550), uint256(0x1391ac3b7b93b746e3e4a111bbb2b848557d053d2d59cb1ff17c9e543c8ec6a7));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x2c21a8fbd19a5118a17de8ea98a88cf9292290bf184fb32f57486d99130bf3bb), uint256(0x1d01e7167240e2641a8d1ab59e7d68c4a6ca31d47b01fee9cb5988fef1d86494));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }
    function verifyTx(
            Proof memory proof, uint[8] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](8);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}
