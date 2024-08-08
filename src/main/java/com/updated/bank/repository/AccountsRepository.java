package com.updated.bank.repository;

import com.updated.bank.model.Accounts;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AccountsRepository extends CrudRepository<Accounts, Long> {

    Optional<Accounts> findByCustomerId(long customerId);

}
