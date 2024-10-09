use starknet::{
    accounts::{Account, ExecutionEncoding, SingleOwnerAccount},
    core::{
        types::{BlockId, BlockTag, Call, Felt, TransactionReceiptWithBlockInfo, FunctionCall},
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
use tokio;
use std::future::Future;

pub async fn assert_poll<F, Fut>(f: F, polling_time_ms: u64, max_poll_count: u32)
where
    F: Fn() -> Fut,
    Fut: Future<Output = bool>,
{
    for _poll_count in 0..max_poll_count {
        if f().await {
            return; 
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(polling_time_ms)).await;
    }

    panic!("Max poll count exceeded.");
}

pub async fn get_transaction_receipt(
    rpc: &JsonRpcClient<HttpTransport>,
    transaction_hash: Felt,
) -> TransactionReceiptWithBlockInfo {
    // there is a delay between the transaction being available at the client
    // and the sealing of the block, hence sleeping for 500ms
    assert_poll(|| async { rpc.get_transaction_receipt(transaction_hash).await.is_ok() }, 500, 20).await;

    rpc.get_transaction_receipt(transaction_hash).await.unwrap()
}

pub async fn get_balance(
    rpc: &JsonRpcClient<HttpTransport>,
    address: Felt,
) -> Felt {
    let eth_token_address =
        Felt::from_hex("0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7")
            .unwrap();
    let call_result =
        rpc
            .call(
                FunctionCall {
                    contract_address: eth_token_address,
                    entry_point_selector: get_selector_from_name("balanceOf").unwrap(),
                    calldata: vec![
                        address
                    ],
                },
                BlockId::Tag(BlockTag::Latest),
            )
            .await
            .expect("failed to call contract");
    let balance = call_result[0];
    balance
}


#[tokio::main]
async fn main() {
    let provider = JsonRpcClient::new(HttpTransport::new(
        Url::parse("http://localhost:9944").unwrap(),
    ));

    let provider2 = JsonRpcClient::new(HttpTransport::new(
        Url::parse("http://localhost:9944").unwrap(),
    ));

    let signer = LocalWallet::from(SigningKey::from_secret_scalar(
        Felt::from_hex("0x76f2ccdb23f29bc7b69278e947c01c6160a31cf02c19d06d0f6e5ab1d768b86").unwrap(),
    ));
    let address_a = Felt::from_hex("0x3bb306a004034dba19e6cf7b161e7a4fef64bc1078419e8ad1876192f0b8cd1").unwrap();
    let address_b = Felt::from_hex("0x5e9e93c6235f8ae6c2f4f0069bd30753ec21b26fbad80cfbf5da2c1bc573d69").unwrap();
    let eth_token_address =
        Felt::from_hex("0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7")
            .unwrap();
    
    let chain_id = provider.chain_id().await.unwrap();

    let mut account = SingleOwnerAccount::new(
        provider,
        signer,
        address_a,
        chain_id,
        ExecutionEncoding::New,
    );

    account.set_block_id(BlockId::Tag(BlockTag::Pending));

    let balance_before_a = get_balance(&provider2, address_a).await;
    let balance_before_b = get_balance(&provider2, address_b).await;

    let result = account
        .execute_v1(vec![Call {
            to: eth_token_address,
            selector: get_selector_from_name("transfer").unwrap(),
            calldata: vec![felt!("0x5e9e93c6235f8ae6c2f4f0069bd30753ec21b26fbad80cfbf5da2c1bc573d69"), felt!("10000000000"), Felt::ZERO],
        }]).max_fee(Felt::ZERO)
        .send()
        .await
        .unwrap();

    println!("Transaction hash: {:#064x}", result.transaction_hash);

    let receipt = get_transaction_receipt(&provider2, result.transaction_hash).await;
    println!("Transaction receipt: {:?}", receipt);

    

    // sleep for more than block time?
    println!("Sleeping for 12 seconds (my block time is 10 seconds)");
    tokio::time::sleep(tokio::time::Duration::from_secs(12)).await;

    let balance_after_a = get_balance(&provider2, address_a).await;
    let balance_after_b = get_balance(&provider2, address_b).await;

    println!("Balance of A before: {}", balance_before_a);
    println!("Balance of A after: {}", balance_after_a);

    println!("Balance of B before: {}", balance_before_b);
    println!("Balance of B after: {}", balance_after_b);

    assert_eq!(balance_before_a, balance_after_a+Felt::from_dec_str("10000000000").unwrap());
    assert_eq!(balance_before_b+Felt::from_dec_str("10000000000").unwrap(), balance_after_b);

}