import Buffer from 'buffer';
import './App.css';
import { useState } from 'react';
import { createSelfTxPsbt } from './inscriptionUtils';
window.Buffer = window.Buffer || require("buffer").Buffer;

function App() {
  const [accounts, setAccounts] = useState([]);
  const [network, setNetwork] = useState('not connected');
  const [balance, setBalance] = useState('0');
  const [psbt, setPsbt] = useState(null);

  const connect = async () => {
    if (!window.unisat) {
      alert('Unisat not found');
      return;
    }
    try {
      let accounts = await window.unisat.requestAccounts();
      setAccounts(accounts);
      let network = await window.unisat.getNetwork();
      setNetwork(network);
      let balance = await window.unisat.getBalance(accounts[0]);
      setBalance(balance.total);
    } catch (error) {
      alert('Error: ' + error.message);
    } 
  }

  const disconnect = async () => {
    // await window.unisat.disconnect();
    setAccounts([]);
  }

  const signPsbt = async () => {
    // create a bitcoin psbt
    const psbt = createSelfTxPsbt(accounts[0]);
    console.log({psbt})
    const bsbtSigned = await window.unisat.signPsbt(
      psbt.toBase64(), //psbt base64
      {
        autoFinalized:false,
        toSignInputs:[
          {
            index: 0,
            address: accounts[0],
          },
        ]
      },);
    console.log({bsbtSigned})
  }

  const sendPsbt = async () => {
    // build the bitcoin transaction and send for execution
  }

  return (
    <div className="App">
      <div className="App-header">
        <button onClick={() => accounts.length ? disconnect() : connect()} >{accounts.length ? 'Disconnect' : 'Connect' }</button>
      </div>
      <div className='content'>
        <h2>Accounts</h2>
        <ul>
          {accounts.map(account => <li key={account}>{account}</li>)}
        </ul>
        <h2>Network</h2>
        <ul>{network}</ul>
        <h2>Balance</h2>
        <ul>{balance} sats</ul>
        <h2>Sign PSBT</h2>
        <ul>TRANSFER ALL BACK TO SELF <button onClick={() => signPsbt()}>SIGN</button> <button onClick={() => sendPsbt()}>SEND</button></ul>
      </div>
    </div>
  );
}

export default App;
