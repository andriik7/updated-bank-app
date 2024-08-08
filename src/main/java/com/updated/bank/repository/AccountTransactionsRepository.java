package com.updated.bank.repository;

import com.updated.bank.model.AccountTransactions;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AccountTransactionsRepository extends CrudRepository<AccountTransactions, String> {

	List<AccountTransactions> findByCustomerIdOrderByTransactionDtDesc(long customerId);

}
