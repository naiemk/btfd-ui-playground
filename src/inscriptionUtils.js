import { witnessStackToScriptWitness } from 'bitcoinjs-lib/src/psbt/psbtutils';
import { testnet, bitcoin, regtest } from 'bitcoinjs-lib/src/networks';
import { assert } from 'minimalistic-assert';
import ElectrumClient from 'electrum-client';
import * as bitcoinjsLib from 'bitcoinjs-lib';

const encoder = new TextEncoder()

function toXOnly(pubkey) {
  return pubkey.subarray(1, 33)
}

function createTextInscription({ text, postage = 10000 }) {
  const contentType = Buffer.from(encoder.encode('text/plain;charset=utf-8'))
  const content = Buffer.from(encoder.encode(text))
  return { contentType, content, postage }
}

function createInscriptionScript({ xOnlyPublicKey, inscription }) {
  assert(xOnlyPublicKey instanceof Buffer, `xOnlyPublicKey must be a Buffer`)
  assert(inscription, `inscription is required`)
  assert(inscription.content instanceof Buffer, `inscription.content must be a Buffer`)
  assert(inscription.contentType instanceof Buffer, `inscription.content must be a Buffer`)
  const protocolId = Buffer.from(encoder.encode('ord'))
  return [
    xOnlyPublicKey,
    bitcoinjsLib.opcodes.OP_CHECKSIG,
    bitcoinjsLib.opcodes.OP_0,
    bitcoinjsLib.opcodes.OP_IF,
    protocolId,
    1,
    1, // ISSUE, Buffer.from([1]) is replaced to 05 rather asMinimalOP than 0101 here https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/src/script.js#L53
    // this may not be an issue but it generates a different script address. Unsure if ordinals indexer detect 05 as the content type separator
    inscription.contentType,
    bitcoinjsLib.opcodes.OP_0,
    inscription.content,
    bitcoinjsLib.opcodes.OP_ENDIF,
  ]
}

function createCommitTxData({ network, publicKey, inscription }) {
  assert(publicKey, 'encodePublic is required')
  assert(inscription, 'inscription is required')
  const xOnlyPublicKey = toXOnly(publicKey)
  const script = createInscriptionScript({ xOnlyPublicKey, inscription })

  const outputScript = bitcoinjsLib.script.compile(script)

  const scriptTree = {
    output: outputScript,
    redeemVersion: 192,
  }

  const scriptTaproot = bitcoinjsLib.payments.p2tr({
    internalPubkey: xOnlyPublicKey,
    scriptTree,
    redeem: scriptTree,
    network,
  })

  const tapleaf = scriptTaproot.hash.toString('hex')

  const revealAddress = scriptTaproot.address
  const tpubkey = scriptTaproot.pubkey.toString('hex')
  const cblock = scriptTaproot.witness?.[scriptTaproot.witness.length - 1].toString('hex')

  return {
    script,
    tapleaf,
    tpubkey,
    cblock,
    revealAddress,
    scriptTaproot,
    outputScript,
  }
}

async function createRevealTx({ network, commitTxData, commitTxResult, toAddress, amount, signer }) {
  assert(commitTxData, `commitTxData is required`)
  assert(commitTxResult, `commitTxResult is required`)
  assert(toAddress, `toAddress is required`)
  assert(typeof amount === 'number', `amount must be a number`)

  const { cblock, scriptTaproot, outputScript } = commitTxData

  const tapLeafScript = {
    leafVersion: scriptTaproot.redeemVersion, // 192 0xc0
    script: outputScript,
    controlBlock: Buffer.from(cblock, 'hex'),
  }

  const psbt = new bitcoinjsLib.Psbt({ network })
  psbt.addInput({
    hash: commitTxResult.txId,
    index: commitTxResult.sendUtxoIndex,
    witnessUtxo: { value: commitTxResult.sendAmount, script: scriptTaproot.output },
    tapLeafScript: [tapLeafScript],
  })

  psbt.addOutput({
    value: amount, // generally 1000 for nfts, 549 for brc20
    address: toAddress,
  })

  psbt = bitcoinjsLib.Psbt.fromBase64(await signer(psbt.toBase64()))

  const signature = psbt.data.inputs[0].tapScriptSig[0].signature.toString('hex')

  // We have to construct our witness script in a custom finalizer

  const customFinalizer = (_inputIndex, input) => {
    const witness = [input.tapScriptSig[0].signature]
      .concat(outputScript)
      .concat(tapLeafScript.controlBlock)

    return {
      finalScriptWitness: witnessStackToScriptWitness(witness),
    }
  }

  psbt.finalizeInput(0, customFinalizer)

  const tx = psbt.extractTransaction()

  const rawTx = tx.toBuffer().toString('hex')
  const txId = tx.getId()

  const virtualSize = tx.virtualSize()

  return {
    txId,
    rawTx,
    inscriptionId: `${txId}i0`,
    virtualSize,
    signature,
  }
}

export async function createSelfTxPsbt(isTestnet, account) {
  // Get utxos for the account
  const network = isTestnet ? testnet : bitcoin
  var utxos = await getUTXOs(account, network);
  console.log("Got utxos", utxos);
  if (utxos.length === 0) {
      throw new Error('No UTXOs available for this address.');
  }
  let sendAmount = 1000;
  const psbt = new bitcoinjsLib.Psbt({ network: isTestnet ? testnet : bitcoin  })
  const tapLeafScript = {
      leafVersion: '', //scriptTaproot.redeemVersion, // 192 0xc0
      script: '', // outputScript,
      controlBlock: Buffer.from('cblock', 'hex'),
  }
  const utxo = utxos[0];
  psbt.addInput({
    hash: utxo.txid,
    index: utxo.vout,
    witnessUtxo: { value: utxo.value, script: '', /*scriptTaproot.output */ },
    tapLeafScript: [tapLeafScript],
  })

  psbt.addOutput({
    value: sendAmount, // generally 1000 for nfts, 549 for brc20
    address: account, // send back
  })
}

async function createCommitAndRevealTx(encoded_call) {
    const secret = 'fc7458de3d5616e7803fdc81d688b9642641be32fee74c4558ce680cac3d4111'
    const privateKey = Buffer.from(secret, 'hex')
    const keypair = {}// ECPair.fromPrivateKey(privateKey, regtest);
    const publicKey = keypair.publicKey
    const { address } = bitcoin.payments.p2pkh({ pubkey: publicKey, network: bitcoin.networks.regtest });
    console.log({ address });
    // console.log("HERER");
    const network = regtest;
    const inscription = createTextInscription({ text: encoded_call });
    const commitTxData = createCommitTxData({ publicKey, inscription });
    console.log(commitTxData);
    // Get the UTXOs (unspent transaction outputs) for the address
    var utxos = await getUTXOs(address, network);
    console.log("Got utxos", utxos);
    if (utxos.length === 0) {
        throw new Error('No UTXOs available for this address.');
    }
    // Create a new Psbt (Partially Signed Bitcoin Transaction)
    const psbt = new bitcoin.Psbt({ network });
    let sendAmount = 1000;
    const { cblock, scriptTaproot, outputScript } = commitTxData
    const tapLeafScript = {
        leafVersion: scriptTaproot.redeemVersion, // 192 0xc0
        script: outputScript,
        controlBlock: Buffer.from(cblock, 'hex'),
    }
    const utxo = utxos[0];
    // Add the UTXOs as inputs to the transaction
    psbt.addInput({
        hash: utxo.txid,
        index: utxo.vout,
        witnessUtxo: { value: utxo.value, script: scriptTaproot.output },
        tapLeafScript: [tapLeafScript],
    });
    psbt.addOutput({
        value: 1000, // generally 1000 for nfts, 549 for brc20
        address: "bcrt1pvu2s0vhdzlak28s2hh9trpksgaa2zeh8cjatwry8z2qdld769d8s0sr4rr",
    });
    psbt.addOutput({
        value: utxo.value - 1000 - 500, // generally 1000 for nfts, 549 for brc20
        address: address,
    });
    await psbt.signInput(0, keypair)
    console.log("processed utxos");
    //const signature = psbt.data.inputs[0].tapScriptSig[0].signature.toString('hex')
    // We have to construct our witness script in a custom finalizer
    const customFinalizer = (_inputIndex, input) => {
        const witness = [input.tapScriptSig[0].signature]
            .concat(outputScript)
            .concat(tapLeafScript.controlBlock)
        return {
            finalScriptWitness: witnessStackToScriptWitness(witness),
        }
    }
    psbt.finalizeInput(0, customFinalizer)
    const committx = psbt.extractTransaction();
    console.log(committx);
    const commitrawTx = committx.toBuffer().toString('hex')
    const committxId = committx.getId();
    const toAddress = 'bcrt1pvu2s0vhdzlak28s2hh9trpksgaa2zeh8cjatwry8z2qdld769d8s0sr4rr'
    const padding = 549
    const txSize = 600 + Math.floor(inscription.content.length / 4)
    const feeRate = 2
    const minersFee = txSize * feeRate
    const requiredAmount = 550 + minersFee + padding
    //expect(requiredAmount).toEqual(2301)
    const commitTxResult = {
        txId: committxId,
        sendUtxoIndex: 1,
        sendAmount: requiredAmount,
    }
    const revelRawTx = await createRevealTx({
        commitTxData,
        commitTxResult,
        toAddress,
        privateKey,
        amount: padding,
    });
    console.log(revelRawTx.txId);
    console.log(revelRawTx.rawTx);
    return { commit: committxId, reveal: revelRawTx.txId }
}

async function createAndBroadcastTransaction(amount, privateKeyWIF, inscription, evm_address, method, target_address, chain_id) {
    try {
        // Setup network parameters for regtest
        const network = bitcoin.networks.regtest;
        const { commit, reveal } = await createCommitAndRevealTx(inscription);
        let commitBroadcastResult = await broadcastTransactionToElectrum(commit);
        let revealBroadcastResult = await broadcastTransactionToElectrum(reveal);
        // Decode the private key (WIF format) to keypair
        const privateKey = Buffer.from(privateKeyWIF, 'hex')
        const keyPair = {} // ECPair.fromPrivateKey(privateKey, network);
        console.log(keyPair);
        const { address } = bitcoin.payments.p2pkh({ pubkey: keyPair.publicKey, network: bitcoin.networks.regtest });
        console.log({ address });
    } catch (error) {
        console.error('Error creating or broadcasting transaction:', error);
    }
}

// Function to list unspent transaction outputs (UTXOs)
async function getUTXOs(address, network) {
    const client = new ElectrumClient(50000, 'localhost', 'tcp');
    await client.connect();
    console.log("Connected");
    const scriptHash = bitcoin.crypto.sha256(Buffer.from(bitcoin.address.toOutputScript(address, network))).reverse().toString('hex');
    const utxos = await client.blockchainScripthash_listunspent(scriptHash);
    // const header = await client.blockchain_relayfee();
    console.log('utxos:', utxos)
    return await Promise.all(utxos.map(async utxo => {
        const tx = await client.blockchainTransaction_get(utxo.tx_hash, true);
        console.log(tx);
        return {
            txid: utxo.tx_hash,
            vout: utxo.tx_pos,
            value: utxo.value,
            hex: tx
        };
    }));
}

async function broadcastTransactionToElectrum(txHex) {
    try {
        const client = new ElectrumClient(50000, 'localhost', 'tcp');
        await client.connect();
        console.log("Connected");
        const result = await client.blockchainTransaction_broadcast(txHex);
        // const header = await client.blockchain_relayfee();
        console.log('result:', result)
        return result;
    } catch (error) {
        console.error('Error posting transaction:', error.message);
        throw error;
    }
}
