#!/usr/bin/env bash
i=0

while true; do
    PREV_BALANCE=$(fedimint-cli ng info | jq -r '.total_msat')
    INVOICE=$(lncli addinvoice --amt_msat 3000 | jq -r '.payment_request')
    #echo "Previous Balance: $PREV_BALANCE"
    echo "Attempt: $i Paying invoice: $INVOICE"
    fedimint-cli ng ln-pay $INVOICE
    POST_BALANCE=$(fedimint-cli ng info | jq -r '.total_msat')
    #echo "Post Balance: $POST_BALANCE"
    DIFF=$((PREV_BALANCE - POST_BALANCE))
    echo "DIFF: $DIFF"

    if [ "$DIFF" -ne 3030 ]; then
        break
    fi

    if [ "$i" -eq 400 ]; then
        echo "four hundred successful payments"
        break
    fi

    sleep 3
    ((i+=1))
done
