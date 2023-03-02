/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.eci.arsw.blacklistvalidator;

import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author hcadavid
 */
public class HostBlackListsValidator {

    LinkedList<ListThread> threads=new LinkedList<>();
    LinkedList<Integer> blackListOcurrences=new LinkedList<>();

    /**
     * Check the given host's IP address in all the available black lists,
     * and report it as NOT Trustworthy when such IP was reported in at least
     * BLACK_LIST_ALARM_COUNT lists, or as Trustworthy in any other case.
     * The search is not exhaustive: When the number of occurrences is equal to
     * BLACK_LIST_ALARM_COUNT, the search is finished, the host reported as
     * NOT Trustworthy, and the list of the five blacklists returned.
     * //@param ipaddress suspicious host's IP address.
     * @return  Blacklists numbers where the given host's IP address was found.
     */


    public List<Integer> checkHost(String ipaddress, int N){
        divide(ipaddress,N);
        comenzar();
        while (true){
            if (!threads.getLast().isAlive()){
                return threads.getLast().getBlackListOcurrences();
            }
        }
    }

    public void comenzar(){
        for (ListThread s: threads){
            s.start();
        }
    }

    public void divide(String ipaddress,int N){
        HostBlacklistsDataSourceFacade skds=HostBlacklistsDataSourceFacade.getInstance();
        if (N % 2 != 0){
            int val = skds.getRegisteredServersCount() / N;
            int a = 0;
            for (int i=0;i < N ;i++){
                ListThread x = new ListThread(ipaddress,0,val,blackListOcurrences);
                threads.add(x);
                a+= val;
            }
        }else{
            int res = skds.getRegisteredServersCount() % N;
            int val = skds.getRegisteredServersCount() / N;
            int a = 0;
            for (int i=0;i < N ;i++){
                ListThread x = new ListThread(ipaddress,0,val,blackListOcurrences);
                threads.add(x);
                if (i == N -1){
                    a+= val;
                    a+= res;
                }
                a+= val;
            }
        }
    }

    
    
    
}
