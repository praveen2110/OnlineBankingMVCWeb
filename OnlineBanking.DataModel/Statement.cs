﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool
//     Changes to this file will be lost if the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------
namespace OnlineBanking.DataModel
{
	using System;
	using System.Collections.Generic;
	using System.Linq;
	using System.Text;
    using System.ComponentModel.DataAnnotations;

    /// <summary>
    /// The transactions and the resulting balance for an account for a given month. 
    /// The requirements are not clear on this, should this be an entity, or is this a collection of other entities. 
    /// We will have to resolve this before we start coding it. In the mean time, it has been captured as an entity.
    /// Probably, this wil work the same way that the "TransactionLog" DataModel class works.
    /// </summary>
	public class Statement
	{
        /// <summary>
        /// The ID of the statement.
        /// </summary>
        [Key]
        [MaxLength(25)]
        public string statementId
        {
            get;
            set;
        }

        /// <summary>
        /// The account number of the associated account.
        /// </summary>
        [MaxLength(25)]
        public string accountNumber
        {
            get;
            set;
        }

        /// <summary>
        /// The month of the statement.
        /// </summary>
        public Double month
        {
            get;
            set;
        }

        /// <summary>
        /// The transactions that make up the statement.
        /// </summary>
        [MaxLength(255)]
        public IEnumerable<TransferTransaction> statementData
        {
            get;
            set;
        }

        /// <summary>
        /// Reads the transactions up through a given month and produces a balance.
        /// </summary>
        /// <param name="accountNumber">The account number to get the balance of.</param>
        /// <param name="month">The month to produce the statement for.</param>
        /// <returns>The balance of the account at the end of the given month.</returns>
        public virtual Statement ReadBalance(string accountNumber, Double month)
        {
            throw new System.NotImplementedException();
        }

	}
}
