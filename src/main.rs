use starknet::{
    accounts::{Account, ExecutionEncoding, SingleOwnerAccount},
    core::{
        chain_id,
        types::{BlockId, BlockTag, Call, Felt},
        utils::get_selector_from_name,
    },
    macros::felt,
    providers::{
        jsonrpc::{HttpTransport, JsonRpcClient},
        Provider,
        Url,
    },
    signers::{LocalWallet, SigningKey},
};
use starknet_api::core::{ChainId, ContractAddress, PatriciaKey};
use tokio;

#[tokio::main]
async fn main() {
    let provider = JsonRpcClient::new(HttpTransport::new(
        Url::parse("http://localhost:9944").unwrap(),
    ));

    let signer = LocalWallet::from(SigningKey::from_secret_scalar(
        Felt::from_hex("0x76f2ccdb23f29bc7b69278e947c01c6160a31cf02c19d06d0f6e5ab1d768b86").unwrap(),
    ));
    let address = Felt::from_hex("0x5e9e93c6235f8ae6c2f4f0069bd30753ec21b26fbad80cfbf5da2c1bc573d69").unwrap();
    let eth_token_address =
        Felt::from_hex("0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7")
            .unwrap();
    
    let chain_id = provider.chain_id().await.unwrap();

    let mut account = SingleOwnerAccount::new(
        provider,
        signer,
        address,
        chain_id,
        ExecutionEncoding::New,
    );

    // `SingleOwnerAccount` defaults to checking nonce and estimating fees against the latest
    // block. Optionally change the target block to pending with the following line:
    account.set_block_id(BlockId::Tag(BlockTag::Pending));

    let result = account
        .execute_v1(vec![Call {
            to: eth_token_address,
            selector: get_selector_from_name("transfer").unwrap(),
            calldata: vec![felt!("0x1234"), felt!("100"), Felt::ZERO],
        }])
        .send()
        .await
        .unwrap();

    println!("Transaction hash: {:#064x}", result.transaction_hash);
}